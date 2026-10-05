#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
struct range {
  uint64_t start, size;
  char name[128];
};
static struct range ranges[1024];
static unsigned count, phase;
static uint64_t callback_count;
static void counted(unsigned cpu, void *unused) {
  (void)cpu;
  (void)unused;
  callback_count++;
}
static uint64_t marker;
static FILE *output;
static struct qemu_plugin_scoreboard *score;
static qemu_plugin_u64 entry(unsigned index) {
  return (qemu_plugin_u64){score, index * sizeof(uint64_t)};
}
static void snapshot(void *unused) {
  (void)unused;
  for (unsigned i = 0; i <= count; i++) {
    fprintf(output, "%u,%s,%" PRIu64 "\n", phase,
            i < count ? ranges[i].name : "outside_symbols",
            qemu_plugin_u64_sum(entry(i)));
  }
  fprintf(output, "%u,independent_callback_total,%" PRIu64 "\n", phase,
          callback_count);
  fflush(output);
}
static void finish(void *unused) {
  snapshot(unused);
  fclose(output);
  qemu_plugin_scoreboard_free(score);
}
static void checkpoint(unsigned cpu, void *unused) {
  snapshot(unused);
  for (unsigned i = 0; i <= count; i++)
    qemu_plugin_u64_set(entry(i), cpu, 0);
  callback_count = 0;
  phase++;
}
static void translate(struct qemu_plugin_tb *tb, void *unused) {
  (void)unused;
  for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
    struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
    uint64_t address = qemu_plugin_insn_vaddr(insn);
    unsigned bucket = count;
    for (unsigned j = 0; j < count; j++)
      if (address >= ranges[j].start &&
          address - ranges[j].start < ranges[j].size) {
        bucket = j;
        break;
      }
    if (address == marker)
      qemu_plugin_register_vcpu_insn_exec_cb(insn, checkpoint,
                                             QEMU_PLUGIN_CB_NO_REGS, NULL);
    qemu_plugin_register_vcpu_insn_exec_cb(insn, counted,
                                           QEMU_PLUGIN_CB_NO_REGS, NULL);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        insn, QEMU_PLUGIN_INLINE_ADD_U64, entry(bucket), 1);
  }
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  if (argc != 2 || !info->system_emulation || info->system.smp_vcpus != 1 ||
      strcmp(info->target_name, "x86_64"))
    return -1;
  if (strncmp(argv[0], "ranges=", 7) || strncmp(argv[1], "output=", 7))
    return -1;
  FILE *input = fopen(argv[0] + 7, "r");
  if (!input)
    return -1;
  while (count < 1024 &&
         fscanf(input, "%" SCNx64 " %" SCNx64 " %127s", &ranges[count].start,
                &ranges[count].size, ranges[count].name) == 3) {
    if (!strcmp(ranges[count].name, "perf_reset"))
      marker = ranges[count].start;
    count++;
  }
  int valid = feof(input) && count && marker;
  fclose(input);
  if (!valid)
    return -1;
  output = fopen(argv[1] + 7, "wx");
  if (!output)
    return -1;
  fprintf(output, "phase,symbol,dispatched_instructions\n");
  score = qemu_plugin_scoreboard_new((count + 1) * sizeof(uint64_t));
  qemu_plugin_register_vcpu_tb_trans_cb(id, translate, NULL);
  qemu_plugin_register_atexit_cb(id, finish, NULL);
  return 0;
}
