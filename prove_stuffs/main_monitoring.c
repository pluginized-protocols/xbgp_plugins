//
// Created by thomas on 27/04/21.
//

extern uint64_t count_as_path(args_t *args UNUSED);

int main(void) {
    args_t args;
    uint64_t ret_val;

    ret_val = count_as_path(&args);

    return 0;
}