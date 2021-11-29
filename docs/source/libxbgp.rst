=======
libxBGP
=======

libxBGP is a library that contains all the internal mechanisms to make a
BGP implementation xBGP compliant. It include a way to run xBGP programs
into eBPF virtual machine. Its API and macro definitions allows
to easily adapt the BGP implementation to load the library and add insertion
points throughout the code.

To execute xBGP program, libxBGP relies on a userspace eBPF virtual machine.
The original project can be found on `GitHub <https://github.com/iovisor/ubpf>`_.
However, our version is adapted to add some functionality that we use with our
xBGP programs.

To correctly work, the library must be initialized by two main components :

1. The list of insertion points
2. The list of API function to register

The initialization must be done before calling any other insertion point. Otherwise,
the library will be unable to execute any xBGP programs.

The API function to initialize the lib has the following definition

``int init_plugin_manager(proto_ext_fun_t *api_proto, const char *var_state_dir, insertion_point_info_t *insertion_points_array, int dbg, log_config_t *logs);``
    initialize libxBGP.

    ``api_proto`` is the array defining the insertion point

    ``var_state_dir`` directory that libxBGP may use to write data during the course of its operation

    ``insertion_points_array`` declare all the insertion points that will be used in the BGP implementation

    ``dbg`` If the plugin uses a log function, redirects the output to stdin

    ``logs`` add logger destination. syslog is enabled by default.


libxBGP also proposes to load plugins at boot time with a manifest used at input. More details on
how this manifest is structured can be found on the Section