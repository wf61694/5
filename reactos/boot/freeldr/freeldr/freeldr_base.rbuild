<module name="freeldr_base" type="objectlibrary">
	<include base="ReactOS">include/psdk</include>
	<include base="freeldr_base">include</include>
	<include base="freeldr_base">cache</include>
	<include base="ntoskrnl">include</include>
	<include base="cmlib">.</include>
	<define name="__USE_W32API" />
<!--	
	<define name="DEBUG" />
-->
	<define name="_NTHAL_" />
	<define name="_NTSYSTEM_" />
	<compilerflag>-ffreestanding</compilerflag>
	<compilerflag>-fno-builtin</compilerflag>
	<compilerflag>-fno-inline</compilerflag>
	<compilerflag>-fno-zero-initialized-in-bss</compilerflag>
	<compilerflag>-Os</compilerflag>
	<directory name="cache">
		<file>blocklist.c</file>
		<file>cache.c</file>
	</directory>
	<directory name="comm">
		<file>rs232.c</file>
	</directory>
	<directory name="disk">
		<file>disk.c</file>
		<file>partition.c</file>
	</directory>
	<directory name="fs">
		<file>ext2.c</file>
		<file>fat.c</file>
		<file>fs.c</file>
		<file>fsrec.c</file>
		<file>iso.c</file>
		<file>ntfs.c</file>
	</directory>
	<directory name="inifile">
		<file>ini_init.c</file>
		<file>inifile.c</file>
		<file>parse.c</file>
	</directory>
	<directory name="math">
		<file>libgcc2.c</file>
	</directory>
	<directory name="mm">
		<file>meminit.c</file>
		<file>mm.c</file>
	</directory>
	<directory name="reactos">
		<file>registry.c</file>
		<file>binhive.c</file>
		<file>arcname.c</file>
		<file>reactos.c</file>
	</directory>
	<directory name="rtl">
		<file>list.c</file>
	</directory>
	<directory name="ui">
		<file>gui.c</file>
		<file>tui.c</file>
		<file>tuimenu.c</file>
		<file>ui.c</file>
	</directory>
	<directory name="video">
		<file>bank.c</file>
		<file>fade.c</file>
		<file>palette.c</file>
		<file>pixel.c</file>
		<file>video.c</file>
	</directory>
	<directory name="windows">
		<file>conversion.c</file>
		<file>peloader.c</file>
		<file>winldr.c</file>
		<file>wlmemory.c</file>
		<file>wlregistry.c</file>
	</directory>
	<file>freeldr.c</file>
	<file>debug.c</file>
	<file>version.c</file>
	<file>cmdline.c</file>
	<file>machine.c</file>
	<pch>include/freeldr.h</pch>
</module>
