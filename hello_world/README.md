# Hello World Plugins

### CBMC checks example :

```shell
cbmc --depth 800 \
     --pointer-check \
     --memory-leak-check \
     --bounds-check \
     --div-by-zero-check \
     --signed-overflow-check \
     --pointer-overflow-check \
     --unsigned-overflow-check \
     --conversion-check \
     --undefined-shift-check \
     --float-overflow-check \
     --nan-check \
     --pointer-primitive-check \
     -I/hostmnt/libxbgp/ \
     -DPROVERS -DPROVERS_CBMC \
     filter_odd_as.c
```

Where :
 - `--depth 1024`: how much time loops will be unrolled (512/1024)
 - `--pointer-check ..... --pointer-primitive-check`: which checks 
 cbmc must verify in the program.
 - `-I/include/to/libxbgp/api`: cbmc requires headers to compile the pluglet
 - `-DPROVERS -DPROVERS_CBMC`: tells to cbmc to include annotation related to the proof
 when compiling the pluglet.
 - `filter_odd_as.c`: the pluglet to verify

### SEAHORN checks examples

```shell
sea bpf -g \
  --bmc="mono" \
  --inline \
  --crab \
  --track=mem \
  --dsa=sea-cs \
  -m64 \
  -DPROVERS -DPROVERS_SEAHORN \
  -I/hostmnt/libxbgp \
  filter_odd_as.c
```

Like CBMC, seahorn is required some CLI parameters to verify custom user assertions.
The important parameters in the context of seahorn are the `-D` and `-I` arguments.
- `-D` parameters will be passed to the clang compiler to generate the code associated
to the seahorn code annotation.
- `-I` are the external include directory where lixbgp headers can be found.