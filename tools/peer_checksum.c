/* Authored host-only RFC 1071 checksum oracle. Never linked into a guest.
 * Bounds cover complete Ethernet-sized inputs. Invalid inputs return UINT32_MAX.
 * No headers, allocation, external calls or third-party source. */
_Static_assert(sizeof(unsigned int) == 4, "32-bit result ABI");
unsigned int peer_checksum(const unsigned char *data, unsigned int size) {
  if (size > 1514 || (!data && size))
    return 0xffffffffu;
  unsigned int sum = 0;
  while (size >= 2) {
    sum += ((unsigned int)data[0] << 8) | data[1];
    data += 2;
    size -= 2;
  }
  if (size)
    sum += (unsigned int)data[0] << 8;
  while (sum >> 16)
    sum = (sum & 65535u) + (sum >> 16);
  return (~sum) & 65535u;
}
