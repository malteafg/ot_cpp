#include <crypto.h>
#include <sodium.h>

int main(void) {
  if (sodium_init() == -1) {
    return 1;
  }

  dh();
}
