# Disclaimer

This project has been done under supervision of RedHat reverse engineers. Analysis report is quite complex and there were mutiple students attending Crash(8) course. Imagining the amount of text our supervisors have to read lead me to spicing it up a little...  
  
I'll add relevant memory dump after its authors approval...  
  
Part II.

# Sidenote
VMC = Virtual Memory Core

# Crashdump analysis write up

If there's something strange in your neighborhood  
Who you gonna call? (Inspector Jacques)  
If there's something weird  
And it don't look good  
Who you gonna call? (Inspector Jacques)  
  
  
"Na jistem systemu dochazelo k pravidelnym padum zpusobujicim kernel panic."  
"EN: Certain system crashes regurarly causing kernel panic."  
Inspector Jacques deduction: something isn't right.  
  
Hacker gloves on, let's get into it.  
  
  
\[VMC1\] \[VMC2\]
```
    > set hex
    > mod -S ./usr/lib/debug/lib/modules
```
\[VMC1\]
```
    > bt

    PID: 1559   TASK: ffff8e6675d80fd0  CPU: 6   COMMAND: "find"                    <---- "find" command with 1559 PID  [1]

    ...

     #6 [ffff8e65c003bc20] do_invalid_op at ffffffff93a2b284                        <---- invalid opcode
     #7 [ffff8e65c003bcd0] invalid_op at ffffffff94122b2e
        [exception RIP: d_instantiate+0x69]
        RIP: ffffffff93c33cd9  RSP: ffff8e65c003bd80  RFLAGS: 00010286              <---- instruction pointer stored    [2]
        ^^^^^^^^^^^^^^^^^^^^^
        ...

     #8 [ffff8e65c003bda0] proc_pident_instantiate at ffffffff93c94d5b              <---- something nasty going on?     [3]

        ...

    #14 [ffff8e65c003bf50] system_call_fastpath at ffffffff9411f7d5
        RIP: 00007f99cc53cf25  RSP: 00007ffca94d3238  RFLAGS: 00000246
        RAX: 000000000000004e  RBX: 0000000001da4650  RCX: ffffffffffffffff         <---- syscall getdents
        ^^^^^^^^^^^^^^^^^^^^^
```
How have we caused invalid_op?
```
    > dis -r ffffffff93c33cd9                                                           <---- RIP [2]

    ...                                                                                 <---- no jumps, no RDI modification [4]

    0xffffffff93c33c81 <d_instantiate+0x11>:        cmpq   $0x0,0xb8(%rdi)              <---- first agument [5]
.-- 0xffffffff93c33c89 <d_instantiate+0x19>:        jne    0xffffffff93c33cd9 <d_instantiate+0x69>
|
|   ...                                                                                 <---- no jumps to RIP [2]
|
|   0xffffffff93c33cd7 <d_instantiate+0x67>:        jmp    0xffffffff93c33cb7           <---- unconditional jump
'-> 0xffffffff93c33cd9 <d_instantiate+0x69>:        ud2                                 <---- RIP [2]
```
Looks like we somehow compare the first argument and trap if the comparsion fails.
```
    > sym ffffffff93c33cd9                                                          <---- RIP [2]
    ffffffff93c33cd9 (T) d_instantiate+0x69 ... fs/dcache.c: 1645


    "I suspect I will have to finally just remove the idiotic BUG_ON() concept once and for all,
    because there is NO F*CKING EXCUSE to knowingly kill the kernel." ~Linus Torvalds

    void d_instantiate(struct dentry *entry, struct inode * inode)
    {
        BUG_ON(!hlist_unhashed(&entry->d_alias));                                       <---- killer

        ...

    }

    static inline int hlist_unhashed(const struct hlist_node *h)
    {
        return !h->pprev;
    }
```
The kernel killed itself, because `struct dentry *entry` was not in expected format. That's all for now.  
  
  
  
  
  
  
  
\[VMC2\]
```
    > bt

    PID: 1679   TASK: ffff891276795ee0  CPU: 1   COMMAND: "find"                    <---- same command as [1]

        ...

    #10 [ffff891377763b80] async_page_fault at ffffffff85b16798                     <---- segmentation violation
        [exception RIP: lookup_real+0x11]
        RIP: ffffffff856259a1  RSP: ffff891377763c38  RFLAGS: 00010292              <---- RIP [6]
        ^^^^^^^^^^^^^^^^^^^^^

        ...

    #11 [ffff891377763c50] __lookup_hash at ffffffff856263c2
    #12 [ffff891377763c80] lookup_slow at ffffffff85b0ac17                          <---- target [7]
    #13 [ffff891377763cb8] path_lookupat at ffffffff8562a248                        <---- target caller [8]

        ...

    #20 [ffff891377763f50] system_call_fastpath at ffffffff85b1f7d5
        RIP: 00007fd6e95e66da  RSP: 00007ffe82e136f8  RFLAGS: 00000246
        RAX: 0000000000000106  RBX: 000000000152aaa0  RCX: ffffffffffffffff         <---- syscall newfstatat
        ^^^^^^^^^^^^^^^^^^^^^


    > sym ffffffff856259a1                                                      <---- RIP [6]
    ffffffff856259a1 (t) lookup_real+0x11 ... fs/namei.c: 1370


    static struct dentry *lookup_real(struct inode *dir, struct dentry *dentry, unsigned int flags)
                                        ^^^^^^^^^^^^^                               <---- dir [9], further refered as the BADBOY
    {

        ...                                                                         <---- no badboy modification

        /* Don't create child dentry for a dead directory. */
        if (unlikely(IS_DEADDIR(dir))) {                                            <---- notice IS_DEADDIR macro
            ...
        }

        ...

    }

    #define IS_DEADDIR(inode)   ((inode)->i_flags & S_DEAD)                         <---- dereferencing badboy [9] from above
```
alright, NULL was probably passed and dereferenced afterwards. lookup_real was called by `__lookup_hash`
```
    > sym ffffffff856263c2
    ffffffff856263c2 (t) __lookup_hash+0x42 ... /fs/namei.c: 1394

    static struct dentry *__lookup_hash(struct qstr *name, struct dentry *base, unsigned int flags)
                                                            ^^^^^^^^^^^^^^^^    <---- base [10]
    {

        ...

        return lookup_real(base->d_inode, dentry, flags);                       <---- base->d_inode [10] is passed as the badboy [9]
                            ^^^^^^^^^^^
    }

__lookup_hash is called by lookup_slow [7]

    > sym ffffffff85b0ac17                                                          <---- target [7]
    ffffffff85b0ac17 (t) lookup_slow+0x42 ... fs/namei.c: 1502

    static int lookup_slow(struct nameidata *nd, struct path *path)
                            ^^^^^^^^^^^^^^^^^^                                  <---- nd [11]
    {
        struct dentry *dentry, *parent;

        ...

        parent = nd->path.dentry;                                               <---- base [10]

        ...                                                                     <---- no parent modification

        dentry = __lookup_hash(&nd->last, parent, nd->flags);                   <---- parent (nd->path.dentry) [11] is passed as base [10]

        ...
    }
```
`struct nameidata *nd` is crucial to us as it is passed as the badboy \[9\] in the end
```
    > dis -r ffffffff8562a248 | tail                                                <---- target caller [8]

    ...

    0xffffffff8562a240 <path_lookupat+0x830>:	mov    %r13,%rdi                    <---- r13 contains the address of nd [11]
    0xffffffff8562a243 <path_lookupat+0x833>:	callq  0xffffffff85b0abd5           <---- target [7]
    0xffffffff8562a248 <path_lookupat+0x838>:	test   %eax,%eax                    <---- RET

    > dis lookup_slow | head                                                    <---- target [7]
    ...
    0xffffffff85b0abda <lookup_slow+0x5>:	push   %rbp                         <---- RBP
    ...
    0xffffffff85b0abde <lookup_slow+0x9>:	push   %r14                         <---- R14
    0xffffffff85b0abe0 <lookup_slow+0xb>:	push   %r13                         <---- R13 nd [11]
    ...
```
the stack looks like this
```
  -
|R13|       <---- nd [11]
|R14|
|RBP|
|RET|
  +

    > bt -f
    #12 [ffff891377763c80] lookup_slow at ffffffff85b0ac17
        ffff891377763c88: 0000000000000001 0000000000000001 
        ffff891377763c98: 0000000000000040 ffff891377763d90                     <---- R13 nd [11]
        ffff891377763ca8: 0000000000000008 ffff891377763d48                     <---- R14 RBP
        ffff891377763cb8: ffffffff8562a248                                      <---- RET
    #13 [ffff891377763cb8] path_lookupat at ffffffff8562a248
```
now we have the address of nd - ffff891377763d90, it's finaly time to read the badboy \[9\]
```
    > struct nameidata ffff891377763d90
    struct nameidata {
      path = {
        mnt = 0xffff891275c46320, 
        dentry = 0xffff8912f180f180                                             <---- base [10]
      }, 

      ...

    }
```
we have base \[10\] - 0xffff8912f180f180                                          <---- ends with f180 f180, easy to remember
```
crash> struct dentry 0xffff8912f180f180
struct dentry {

  ...

  d_inode = 0x0,                                                                <--- badboy d_inode [9]

  ...

}
```
Inspector Jacques strikes again! badboy \[9\] == NULL, this explains the segmentation violation. That's it for now.  
    
  
  
  
  
  
\[VMC1\]  
  
The kernel killed itself, because `struct dentry *entry` was not in expected format. We need to hunt for `entry`.  
  
where does `entry` come from? after very lengthy process inspector Jacques was able to reconstruct the relevant source code.
```
    > bt
    PID: 1559   TASK: ffff8e6675d80fd0  CPU: 6   COMMAND: "find"

        ...

     #7 [ffff8e65c003bcd0] invalid_op at ffffffff94122b2e
     #8 [ffff8e65c003bda0] proc_pident_instantiate at ffffffff93c94d5b              <---- [12]
     #9 [ffff8e65c003bdc8] proc_fill_cache at ffffffff93c9547c                      <---- [13]

        ...

    > sym ffffffff93c9547c                                                          <---- [13]
    ffffffff93c9547c (T) proc_fill_cache+0x14c ... /fs/proc/base.c: 1887

    int proc_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
                        ^^^^^^^^^^^^^^^^                                            <---- [14]
        const char *name, int len,
        instantiate_t instantiate, struct task_struct *task, const void *ptr)
    {
        struct dentry *child, *dir = filp->f_path.dentry;                           <---- dir is filp->f_path.dentry [14]

        ...

        if (!child) {
            struct dentry *new;
                          ^^^^^
            new = d_alloc(dir, &qname);                                             <---- creation of dentry [15] dir is related to [14]
            if (new) {
                child = instantiate(dir->d_inode, new, task, ptr);                  <---- instantiate is a function pointer and we know [12] was called next
                                                 ^^^^^

                ...

            }
        }  

        ...

    }

    > sym ffffffff93c94d5b                                                              <---- [12]
    ffffffff93c94d5b (t) proc_pident_instantiate+0x7b ... /include/linux/dcache.h: 295  <---- we have to deal with (nested) inlining [16]

    static struct dentry *proc_pident_instantiate(struct inode *dir,
        struct dentry *dentry, struct task_struct *task, const void *ptr)
        ^^^^^^^^^^^^^^^^^^^^^                                                           <---- [15]
    {

        ...

        d_set_d_op(dentry, &pid_dentry_operations);                                     <---- curiosity [???]

        d_add(dentry, inode);                                                           <---- [16]
                ^^^^                                                                    <---- [15]

        ...

    }


    static inline void d_add(struct dentry *entry, struct inode *inode)                 <---- [16]
    {
        d_instantiate(entry, inode);                                                    <---- [17]
        ...             ^^^
    }

    void d_instantiate(struct dentry *entry, struct inode * inode)                      <---- [18]
                                        ^^^
    {
        BUG_ON(!hlist_unhashed(&entry->d_alias));                                       <---- killer         
                                ^^^^^^^^^^^^^^
        ...

    }

    static inline int hlist_unhashed(const struct hlist_node *h)                        <---- [19]
    {
        return !h->pprev;
    }
```
this was painful, but we have the code from the creation all the way to the killer.  
we can see, that the proc_fill_cache function creates a dentry (further refered as GOODBOY)  
that is processed by mutiple functions afterwards and in the end the very same goodboy kills the system.  
  
there are two possibilities, either the memmory allocation failed or some of the mediator function messed  
up with goodboy. Inspector Jacques tried luck with the second option (and also with s* ton of other options  
before he even reached this state...)  
  
Inspector task: go through all the functions from the very creation and check every function call that  
might mess with the goodboy.  
  
to demonstrate the horror Ispector had to go through while checking all of the mentioned functions and  
search for source codes, Jacues presents: the cursed `d_set_d_op proc_fill_cache` [???] function (further  
refered as the SWAGGER FUNCTION).  
```
void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op)
{

    ...

    if (get_real_dop(dentry))                                   <---- this was the only possibility left to mess with the goodboy
        ...

}
```
the swagger function calls `get_real_dop`. Jacques searched for this function for enormous time, but all  
he could get were tutorials on "how to get real dope", "how to improve your swagger", snapback ads etc. digging through  
the pile of street rap and lowpants culture Jacques tried to add up some keywords including "kernel" or "linux",  
but apparently the swagger dominates 'em all.  
  
looking at the source code (apart from the swagger function) Inspector found out, that nothing messes with the  
dentry.  
  
Inspector task: analyse the goodboy and then check the allocation
```
     #7 [ffff8e65c003bcd0] invalid_op at ffffffff94122b2e
        [exception RIP: d_instantiate+0x69]
        RIP: ffffffff93c33cd9  RSP: ffff8e65c003bd80  RFLAGS: 00010286          <---- target [2]
            ^^^^^^^^^^^^^^^^^^
        ...

     #8 [ffff8e65c003bda0] proc_pident_instantiate at ffffffff93c94d5b          <---- target caller [3]
```
d_instantiate's [18] first argument is the goodboy
```
    > dis -r ffffffff93c94d5b | tail                                                <---- target caller [3]

    ...

    0xffffffff93c94d53 <proc_pident_instantiate+0x73>:	mov    %r13,%rdi            <---- goodboy
    0xffffffff93c94d56 <proc_pident_instantiate+0x76>:	callq  0xffffffff93c33c70   <---- target [2]
    0xffffffff93c94d5b <proc_pident_instantiate+0x7b>:	mov    %r13,%rdi            <---- RET

    > dis d_instantiate | head                                                  <---- target [2]
    ...
    0xffffffff93c33c75 <d_instantiate+0x5>:	push   %rbp                         <---- RBP
    ...
    0xffffffff93c33c79 <d_instantiate+0x9>:	push   %r13                         <---- R13
```
the stack looks like this
```
  -
|R13|       <---- goodboy
|RBP|
|RET|
  +

    > bt -f

        ffff8e65c003bd88: ffffffff94237ac8 ffff8e6672407240                         <----     R13
        ffff8e65c003bd98: ffff8e65c003bdc0 ffffffff93c94d5b                         <---- RBP RET
     #8 [ffff8e65c003bda0] proc_pident_instantiate at ffffffff93c94d5b
```
goodboys address ends with 7240 7240 and is easy to remember aswel, what are the odds?!
```
    > struct dentry ffff8e6672407240                                            <---- goodboy
    struct dentry {

        ...

      d_inode = 0xffff8e66795e85a8,                                             <---- unlike the badboy's a goodboy's d_inode seems fine

        ...

      d_alias = {                                                               <---- killer
        next = 0x0, 
        pprev = 0xffff8e66795e86c0                                              <---- supposed to be NULL
      }
    }
```
now we know why killer macro triggered. we know that none of the mediator function touch `pprev`, this means  
it must be set in the allocation function `new = d_alloc(dir, &qname);`
```
    struct dentry *d_alloc(struct dentry * parent, const struct qstr *name)
    {
        struct dentry *dentry = __d_alloc(parent->d_sb, name);                          <---- [20]

        ...

        list_add(&dentry->d_u.d_child, &parent->d_subdirs);                             <---- [21]

        ...

    }

    struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
    {
        struct dentry *dentry;

        dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);                        <---- allocation

        ...

        if (((long)dentry & 0xffff) == (((long)dentry >> 16) & 0xffff))             <---- some mumbo jumbo
            kmem_cache_free(dentry_cache, dentry);

        ...

        INIT_HLIST_NODE(&dentry->d_alias);                                          <---- the only place messing with dentry->d_alias (goodboy)
        INIT_LIST_HEAD(&dentry->d_u.d_child);                                       <---- this get "list_add"ed [21] above [22]

        ...

        return dentry;
    }


    static inline void INIT_HLIST_NODE(struct hlist_node *h)                        <---- looks fine
    {
        h->next = NULL;
        h->pprev = NULL;
    }
```
it's getting a little confusing, so let's sum up. goodboy is created in `d_alloc` and passed through a pile of  
mediator functions later on till it reaches `d_instantiate` where it kills the system, since `entry->d_alias`  
is not NULL. we know that the mediator functions do not mess with the goodboy's `d_alias` and therefore can be  
neglected. the problem is, that we know for sure, that goodboy's `d_alias` has been properly initialised...  
what could have possibly go wrong?  
  
another hint Inspector had was...
```
    > log

    [   59.407180] WARNING: CPU: 3 PID: 1559 at lib/list_debug.c:29 __list_add+0x65/0xc0            <---- PID [1]
    [   59.407198] list_add corruption. next->prev should be prev (ffff8e66f8df3ca0), but was ffff8e66724072d0. (next=ffff8e66724072d0).

        ...

    [   59.407782] WARNING: CPU: 3 PID: 1559 at lib/list_debug.c:36 __list_add+0x8a/0xc0            <---- PID [1]
    [   59.407799] list_add double add: new=ffff8e66724072d0, prev=ffff8e66f8df3ca0, next=ffff8e66724072d0.
```
Inspector thought that there was something wrong with list_add \[21\] function or initialization \[22\]. diggin through  
the code \[21\] \[22\] and reading the memmory of \[14\] (it's obtainable from stack...), since it is eventualy  
passed as second argument of list_add \[21\], Jacques found absolutely nothing that would look even a bit suspicious.  
Jacques is defeated... this simply can not be comprehended...  
  
wait... can't be true... or could it be??? so obvious now!!
```
                                      .#@@@@@@@@@@@@@@@@@@@#.                                      
                                (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(                                
                           ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,                           
                        @@@@@@@@@@@@@@@@@@@%(,.     .,(%@@@@@@@@@@@@@@@@@@&                        
                    .@@@@@@@@@@@@@@,                           ,@@@@@@@@@@@@@@.                    
                  @@@@@@@@@@@@(                                     (@  BARBRA  @                  
                @ __d_alloc @,                                       .  STREISAND @                
              @@@@@@@@@@@@@@@@@                                     @@@@@@@@@@@@@@@@@              
            @@@@@@@@@,*@@@@@@@@@@&                               #@@@@@@@@@@/,@@@@@@@@@            
          @@@@@@@@@    @@@@@@@@@@@@@/                         .@@@@@@@@@@@@@    @@@@@@@@@          
        .@@@@@@@@.      @@@@@@@@@@@@@@@                     @@@@@@@@@@@@@@@      .@@@@@@@@.        
       *@@@@@@@&        @@@@@@@@@@@@@@@@@#               .@@@@@@@@@@@@@@@@%        &@@@@@@@*       
      &@@@@@@@           @@@@@@@@@@@@@@@@@@@,          @@@@@@@@@@@@@@@@@@@           @@@@@@@&      
     @@@@@@@@            *@@@@@@@&&@@@@@@@@@@@@,    &@@@@@@@@@@@@&@@@@@@@/            @@@@@@@@     
    @@@@@@@#              @@@@@@@@.  @@@@@@@@@@@@&@@@@@@@@@@@@/  @@@@@@@@              #@@@@@@@    
   @@@@@@@(                @@@@@@@@    *@@@@@@@@@@@@@@@@@@@@    @@@@@@@@                (@@@@@@@   
  (@@@@@@%                 #@@@@@@@#      @@@@@@@@@@@@@@@*     (@@@@@@@%                 %@@@@@@(  
  @@@@@@@                   @@@@@@@@     /@@@@@@@@@@@@@@@@     @@@@@@@@                   @@@@@@@  
 @@@@@@@                     @@@@@@@@  @@@@@@@@@@@@@@@@@@@@@# @@@@@@@@.                    @@@@@@@ 
.@@@@@@&                     %@@@@@@@@@@@@@@@@@@@,@@@@@@@@@@@@@@@@@@@&                     &@@@@@@.
@@@@@@@                       @@@@@@@@@@@@@@@@@     .@@@@@@@@@@@@@@@@                       @@@@@@@
@@@@@@@                       *@@@@@@@@@@@@@            @@@@@@@@@@@@@                       @@@@@@@
@@@@@@/                     @@@@@@@@@@@@@,                #@@@@@@@@@@@@@                    /@@@@@@
@@@@@@.                  @@@@@@@@@@@@@@@                   @@@@@@@@@@@@@@@(                 .@@@@@@
@@@@@@                *@@@@@@@@@@@@@@@@@&   MUMBO JUMBO    &@@@@@@@@@@@@@@@@@@,               @@@@@@
@@@@@@             *@@@@@@@@@@@@@@@@@@@@@                 @@@@@@@@ @@@@@@@@@@@@@*            @@@@@@
@@@@@@.         .@@@@@@@@@@@@@   ,@@@@@@@@               @@@@@@@@*   .@@@@@@@@@@@@@         .@@@@@@
@@@@@@(       &@@@@@@@@@@@@,      @@@@@@@@*             ,@@@@@@@@       /@@@@@@@@@@@@&      (@@@@@@
@@@@@@@    /@@@@@@@@@@@@#          @@@@@@@@             @@@@@@@@           @@@@@@@@@@@@@#   @@@@@@@
@@@@@@@ (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/@@@@@@@
.@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.
 @@   GOODBOY    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   BADBOY  @@@@ 
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
  (@@@@@@%                            @@@@@@@@.     .@@@@@@@@                            %@@@@@@(  
   @@@@@@@(                           (@@@@@@@@     @@@@@@@@#                           #@@@@@@@   
    @@@@@@@#                           @@@@@@@@%   (@@@@@@@@                           #@@@@@@@    
     @@@@@@@@                          .@@@@@@@@   @@@@@@@@,                          @@@@@@@@     
      &@@@@@@@                          &@@@@@@@@ @@@@@@@@&                         .@@@@@@@&      
       *@@@@@@@&                         @@@@@@@@#@@@@@@@@                         @@@@@@@@*       
        .@@@@@@@@.                       &@@@@@@@@@@@@@@@&                       .@@@@@@@@.        
          @@@@@@@@@                       @@@@@@@@@@@@@@@                       @@@@@@@@@          
            @@@@@@@@@,                    /@@@@@@@@@@@@@(                    ,@@@@@@@@@            
              @@@@@@@@@@                   @@@@@@@@@@@@@                  .@@@@@@@@@@              
                @@@@@@@@@@@                 @@@@@@@@@@@                 @@@@@@@@@@@                
                  @@@@@@@@@@@@#             %@@@@@@@@@&             (@@@@@@@@@@@@                  
                    .@@@@@@@@@@@@@@,         @@@@@@@@@         ,@@@@@@@@@@@@@@.                    
                        @@@@@@@@@@@@@@@@@@@&(/@@@@@@@((&@@@@@@@@@@@@@@@@@@&                        
                           ,@@@@@@@@@@@@@@@  LIST ADD  @@@@@@@@@@@@@@@@@@,                           
                                (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(                                

```
Jacques was sure from the very begining, that this had something to do with Barbra Straisand and satan...  
lets look at the `__d_alloc again`
```
    struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
    {
        struct dentry *dentry;

        dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);                        <---- allocation

        ...

        if (((long)dentry & 0xffff) == (((long)dentry >> 16) & 0xffff))             <---- MUMBO JUMBO
            kmem_cache_free(dentry_cache, dentry);                                  <---- free the cache?

        ...

    }
```
`((long)dentry & 0xffff) == (((long)dentry >> 16) & 0xffff)` checks whether the address is of the following  
format: 0x____ ____ SAME SAME and both, the goodboy and the badboy, match. the memmory gets freed and used afterwards.  
some process/thread uses the cache and rewrites the data. this causes segmentation violation in \[VMC2\] and  
corruption of goodboy->d_alias in \[VMC1\].  
  
dam dam... dam dam... da dam da dam da dam da daaaaaaaaaaaaaaaam.... da da da dam...  
```
                                                         ......,......                                                 
                                                 ..,,,,,,,,,.,,*,,****,...                                             
                                             ..*,,,*,,,,,.,,,,,*,*,,,,,*,,.                                            
                                            ,,*,,**,,,,,,,,,,.,,,,,,,,,,,,,,.                                          
                                          ***,,,*****,**,***,**,,**,,,*,,,***                                          
                                         .,,,..,*,*,,,,,***,,**,*****,,,,,,,,,                                         
                                       ...,..,,****,**////**,,,,**,**/*****,,,,.                                       
                                      .....,,,,,******/*,*,,,,,***,****,***,,...                                       
                                    ......,,***,*/*****,,,,*,,,*****///*,,,,,,....                                     
                                   ....,,,,,*,,,**,,,,.,,****,,,**,,,,,*/*****,...                                     
                                  ..,,,*****,,,*,,,,**,,**,,,******,,**/**,****,,,.                                    
                                 ..,,,,***,,,,*,,*/**////////**//*/**/////,***,,,,*.                                   
                                .....*/,,,***//(##%%&&&&%%&&&%%%%%%&&%&%%##//*****,.                                   
                               ....,*////(%%&&%(((/****,*****,*,**///*****//(#%%#(*,,                                  
                               ,..*/(#%&(/*,..,,,,..,,,,..,,..,,,,............*(%%(*..                               
                              ...*%%/,,.,,.....,,..,,,...........................,*#*,.                              
                             .*#%(,.......,.......,.,...,..........................  . .,.                             
                            ,/#,........,,,,,*,,,,,,,,,***,,,,**,,,,,**,,,.,,..,..... .                                
                          .*(/....*,**/(((((((((((####(####%#################(((#(#(((/****,,..                        
                          **..,**/((#%&%%%%##########%%%%%%%%&&&&&&&&&&&&&&&&&&&&&&&&&&&%%%#((/*.                      
                        ..*/((#%%&@&&%#///////////(((((((//////(((((#######(((#######&&&&&&&&&%(/.                     
                      .,*/((%&@&@&&%%(///////////////(((((((////////((((////((((####(%&&&&&&&&&%#/.                    
                    ..**/#&&&&@&&&&//////****///#%&&&&%%%#(((///////////////(((((((%&&&&&&&&&%%/.                    
                 .,*((%&&@&&&&&&&&%#////*******/((///((#(#%%###///*****//(%&&&%%((///%&&&&&&&&&*.                    
                .*((%%&&&@&&&&&&&#(/*******,*********/////////**,****/(#%&&&&&&//&&&&&&&&&%%/.                     
               .*(#%%&&&&&&&&&&&&&%%/*******,***,*//(##/*/(#(/////*,,*/(((((((((##%((&&&&&&&&/,                      
               ,/#%&&&&&&&%&@@&&&%%#/**,,,,,,,**/((**((%,.*/((////*,,*/((((/((#(**/(%&&&&&&&/*                       
               *(%%&&&&&&(///#&&&%((/**,,,,,,********//*,*///,,****,,*/((/%#%/.*#(*#&&&&&&&%#*                         
               */%&&&&&,//*/%&%(##/,,,,,,,,,,,,,,,*//////,,,,,,*,...,*///#(,*/(/*%&&&&&%%/*                          
               ,*#%&&&&%(#(/**(#((#(*,,,,...........,,,,***,,,,,,,.....*///((//*///&&&&&/.                           
               .,/#%&&&&(((****###(/*,...............,,,,,.....,,,.. ..****//*****/&&&&%#*.                            
                 .(#&&&&&/(*/((//(//*..........................,,..   .*,,****,,,,*%&/.                              
                  ,(#%&&&((//#/*,***................,..........,..    .*,,,,,,,..,*%%#.                                
                   .(%&&&%///(**,,........,,,,,,,,,.........,,,,,.    .,,,,,,,,,,,(#*                                  
                    ./%&&&//*//**,........,,,,,,,,,.......,*,.....   ..,,,,,,,**,,,                                    
                      .#%##*//,,,,.........,,,,,,.......,*,,,**,,,*****,*,,,,****,                 .,**,..             
                       ./%%%,,,,,.........,,,,.........,,..,*/(/**/////***,,,***,,            ,*#&&@@@@@@@@%/,         
                         .#&(,,...........,,.........,,.  ..,**///////*,**,,,***,.         *(%&&&@@@@&%#(((#&&%/       
                          ./&/*.........................,**///(((///*,,,,,,***.       /&@&&&&&%*.            .(*     
                           *&&&(/,......................,*/((#(((/(////*.,,,,,,,      (&@@@&&&*.                 /#.   
                            .*%/**,,.................,*//((##((((////((#*,,,,,,,    .%@@@@@%/                     ,%   
                              *//*,,,,,.............,***////////***////#(/,,,,,,   (&@@@@%/          .            .%/  
                               ,****,,...............,,///((//(#%%%##(//((*,,,.   #@@@@&,             ..           /%* 
                                .///*,,..............,,,.......,,,,,*/////*,,,  .(@@@@(,                           /&/ 
                                 .///**,..........,,,,....,,,**/***,,,****,,,.  #&&@@(         ..                  (&/ 
                                  .*((/,,.......,,,.....,,,***//******,**,,..  *&&&&%         .....               .%%* 
                                    *(#(/,...........,,,,,***********,,,,,.   *%&&&*       ......                ./&*  
                                     */##/,,,,,..........,,....,,,,*,,,,,.    %@&&%      ........                (%%.  
                                       ,(#/*,,,,,....................,,,.    .&@&&/     ......                  ,&&/   
                                         ,#(/**,,,,,.........,.......,,.     .&@@&.    ......                  .%&%    
                                           .*/////,,,,,,,,********,,,,.      .&@@%     ......                 #&@/.    
                                             .*/////*,,************,,         %@@%       .......            *#@@(      
                                              ..//(//////////*****.           *%@&.       ......           /@@&(       
                                            .. ...,*////////////*.             .&@/         .           ,%@@%/         
                                             ...... .*//////////,.              ./&,                  *#&&&/           
                                              .........*///////*.                 .#(.             ,/%&&%,.            
                                               .....   ..,**/*/,                    .%%(,.   .,*(%&&&%/,               
                                                  ...         ,/,                      .#@&&&&@@%/,                    
                                           ,(#(*.   ..       .*##*                      ,&@@&@.                      
                                        .(%%%&&&&/           /#%#/,       ,*.        .,*(###########(.                 
                                     .*((/////(%#*          ,&&&(*/.      ,(*      .,(%%%%%%%%%%%%%###(,               
                                  ,*/*,........,.          /%&&%((%(,       ..  ..*(#%%%%%%%%%%%%%%%%%#/               
                               ,,*,,..         .            ,&#%&(*,.      .,,/(%&&&%%%%&&&&&%&%%%%%/.               
                            .,*,,..                          ,(#%##*.     .,(#%&&&&&&&&&&&&&&&&&%(/.                 
                         .,,,...             .                 (&%(#(/,   ,**#&&&&&&&&@@@&&&&&%%%%%*.                  
                                            .                   ,/%&%(/.**((#%&&&&@&&&&&&&&%%%%%%###(.                 
                                                                 ./%%#(/((((#%%&&&&&&&&&%%%%%%%%%%###.                 
                                                                  .////(######%%&&&%%%%%%%%%%&&&%%%#/                  
                                                                  .//(##(((%%&&&%&&&&&&&&&&&&&&&&/,                    
                                         .                       .((((##((%%%&&&%%%&&%%&&&&&@@&&&%(                    
                                                                ,/((####%%%&&&&&&%%&&&&&@&&&&&&&%%#/.                  
                                                                /((###%%&&&&&&&&&&&%%&&&&&&%%%%%%%%/.                  
                                                              .(####%&&&&@@&&&&%%&&&&%%%%%%%&%%%%%%/.                  
                                                             ,//(##&&&&&&&&&&&&&%%%&&&%&&&&&&&&&*                    
                                                           .,//(##&&&&&&&&&&&&&&%%%%&&&&&&&&&&&@&*.                    
                                                          ,(###%%&&&&@@&&&&@@@&&&&&&&&&&&&&&&&%%%#/                    
                                             .         .(%#%%%&&&&@@@&&&@@@@@@@@&&%&&%%%%%%%%%%%%#*                    

```