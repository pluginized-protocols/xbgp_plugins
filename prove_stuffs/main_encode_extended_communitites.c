//
// Created by thomas on 1/04/21.
//



extern uint64_t generic_encode_attr(args_t *args __attribute__((unused)));

int main(void) {

    uint64_t ret_val;
    args_t arg = {};

    ret_val = generic_encode_attr(&arg);

    return ret_val == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

}