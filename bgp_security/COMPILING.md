# BGP Security Related Plugins

There are two different plugins in this folder.

1. Origin check (rpki ROA "like") plugin
2. Checks if a BGP route comes from customer or provider

We provide a Makefile and a manifest that compile all the .c files 
contained in the folder. However, we provide the manifest for the
origin check plugin. The logic remains the same for the second plugin.

clang and llc me be installed beforehand to be able to run the makefile
as we rely on the clang compiler to generate an ELF eBPF bytecode object.

To run the makefile, you will need to tell where they can find the headers
related to the libxBGP library. libxBGP contains some generic function to
compute math functions, interacting with the memory or directly with the
virtual machine manager.

The plugin can be compiled as the following:

```shell
make LIBXBGP=</path/to/the/"include"/directory/of/libxbgp>
```
