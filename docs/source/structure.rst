Structure of xBGP
=================

To get started, we will first discuss at a high level on the multiple
parts of xBGP. In fact, xBGP's design is composed of multiple sub components :

1. Any BGP implementation
2. libxBGP
3. Plugins
4. xBGP API
5. Insertion point

BGP Implementation
------------------

Our solution is designed to make an actual BGP implementation xBGP compatible.

To simplify the task, we already selected two implementations, BIRD and FRRouting, on
which we applied our patches.

You can find those implementations on the following GitHub repositories :

- BIRD
- FRRouting

libxBGP
-------

If you still would like to adapt your BGP implementation to make it xBGP compatible,
we provide lixBGP. It is a library (written in C) that contains all the required
functions and macros to enable make a BGP implementation xBGP compatible.

More details can be provided on its dedicated repository (put link please)

Plugins
-------

A plugin is a set of xBGP programs implementing a given functionality.
Each xBGP program is written in C and then compiled into eBPF bytecode with
a clang compiler.

Once compiled the xBGP programs is loaded to the xBGP compatible and then run
on its corresponding location.

xBGP API
--------

A plugin cannot directly access to the data structure of the BGP implementation
neither calling their internals functions. Instead, the plugin needs to call an
API function directly provided by the BGP implementation.

You can think that the BGP implementation is a kind a microkernel that execute
plugins. The way to talk and interact with BGP is made through the xBGP API.

There are various API functions, each of them are dedicated on a specific task.
Some functions fetch the data from the BGP internal structure while others will
modify the internal data structure of BGP.

A detailed specification of the xBGP API is provided on its dedicated section.

Insertion Point
---------------

When the plugin has been written, it will be loaded to the BGP implementation.
However, we need to tell the implementation where the plugin must be executed.

With xBGP, plugin are executed in an event based way. When receiving a message
from its peer, BGP systematically traverses important steps that are defined in
the corresponding BGP RFC. First, the BGP update message is parsed, then the update
goes through import filters. If it passes the filters, the route is added to
the RIB and the BGP decision process runs to select the best route among those available
for the same prefix. If a new route is selected, this one will first reach exportation
filters and then serialized to be send on the peers.

We defined insertion points, that correspond to those important BGP steps. A
detailed view of insertion points is described on section [].

xBGP also enables a plugin to be executed in a time based way. Those plugin are not
related to an event of the protocol but rather is executed when a timer is elapsed.
This enable BGP to execute code that are not related to BGP itself.