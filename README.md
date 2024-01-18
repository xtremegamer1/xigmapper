# xigmapper
xigmapper is a driver manual mapper that loads your driver before Vanguard, but after critical system infrastructure has been set up, allowing you to write your bypass without worrying about the intricacies of EFI or the boot process.

# Limitations
xigmapper requires sb off, or for you to manually load the driver's file digest into your tpm (which i don't know how to do). This means that you can only use it against Vanguard on Windows 10, because Windows 11 Vanguard requires sb on, unless you know how to spoof secure boot. 

# Compiling the efi driver
In order to compile the efi driver, you need to clone and build [VisualUefi](https://github.com/ionescu007/VisualUefi), and clone this repo into the same directory that VisualUefi was cloned into. Then, build using Visual Studio.

# Using the driver
In order to use the compiled driver, you must:

Edit the variable g_module_path in hook.c to include the path of the driver that you want to load. The driver you want to load cannot be on a usb device, because usb devices are discovered and loaded by Windows after Vanguard is. 

Then, you must put the compiled .efi driver into a exFAT or FAT32 partitioned drive (usb drives work for this). If you don't have an exFAT or FAT32 partition created, you can use the diskpart utility that comes with Windows to create a new partition on your drive.

Download the [efi shell](https://github.com/tianocore/edk2/blob/edk2-stable201903/ShellBinPkg/UefiShell/X64/Shell.efi), rename it to BOOTX64.efi, and put it into the directory \efi\boot on your FAT partition. 

Then boot to that partition from BIOS, and from the shell navigate to the partition you just booted from (usually fs0:), and load "efi driver.efi". Then load Windows by locating the partition with your Windows installation on it, and then executing "EFI\BOOT\bootmgfw.efi". 

If you did everything right, your driver will be loaded after IoInitSystemPreDrivers (which initializes essential windows OS functionality) and before IopInitializeSystemDrivers (the routine that loads Vanguard and other SYSTEM_START drivers).

# What is this good for?
This mapper should make it more convenient for cheat devs and pasters to bypass Vanguard, by taking away the work that comes with writing an efi driver and dealing with all the associated baggage. Now you just have to write (or paste) a simple Windows kernel driver, and loading it on Vanguard is as simple as editing a string and recompiling. I have tested this myself with a hypervisor that is made to be mapped once the system is already fully booted, and it works with no problem being bootloaded.
