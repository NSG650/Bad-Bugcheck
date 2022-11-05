# Bad Bugcheck !!

Bad apple in the BSOD.

## What is so different about this one?

It uses the framebuffer the same one as the BSOD does. So no bootvid! No more 16 color VGA and no more 640x480 resolution!

It plays the bad apple video when a bug check is called and then in the end restores the original function and calls it. [Yes this messes with the CPU context but we are having fun here sooo]

## How does it work???

There are several parts to this but I will break it down into sub sections. These are the steps performed by the driver in order.

### Hooking into `KeBugCheckEx`
This is the same code as seen in my other project [NoMoreBugCheck](https://github.com/NSG650/NoMoreBugCheck). There are parts to this as well. Such as rehooking KeBugCheckEx to another dummy function incase another thread decides to call a bug check while we are playing bad apple.

### The framebuffer
For Microsoft basic Display Adapter the framebuffer address lies at `0xf0000000 - 0xf7ffffff`. So I just map the memory using `MmMapVideoDisplay`. However that won't work on its own. After poking around with WinDbg and IDA I found out that Most `Bg[c/p/k]` functions [such as `BgpClearScreen`] are called after calling `InbvAcquireDisplayOwnership`. Good thing is its already exported so no extra work needed for that just add the function prototype and call it.
```c
NTKERNELAPI
VOID
InbvAcquireDisplayOwnership(
    VOID
);
```
 I have read on some forums that it is possible to use Dxgk to get the framebuffer address but I was in a hurry and just decided to use a graphics driver that supported every GPU [Microsoft Basic Display Adapter].

### The Image Parsing
Image Parsing is handled by `stb_image.h`. I had to add some defines to make it work. It works well.

### Drawing the image
We just `RtlCopyMemory/memcpy` the raw image data parsed by `stb_image.h`. 

### Restore the Original `KeBugCheckEx`
We restore the original `KeBugCheckEx` function and call it with the paramters it was originally called with.

## Limitations

* Hard coded file path `C:\badapple_out\%d.jpg`
* Only supports Microsoft Basic Display Adapter
* Only runs at 1024x768

Yeah thats all

## How to use it?

You know the routine

1. Enable testsigning and debug mode [Debug mode as KPP would trigger when we hook into `KeBugCheckEx`].
```
bcdedit /set testsignin on
bcdedit /debug on
```

2. Create a service and start it
```
sc.exe create BadBugCheck binPath=C:\Path\To\BadBugCheck!!.sys type=kernel start=demand
sc.exe start BadBugCheck
```
3. Copy over all the frames to `C:\badapple_out` [The code is hardcoded to 5258 frames so you might have to modify that]

4. Cause a bsod!

## Notes

- If you want to revert the changes just simply unload the driver.
```
sc.exe stop BadBugCheck
```
- Disable your graphics driver before running it.