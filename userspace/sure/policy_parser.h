/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SURE_POLICY_PARSER_H
#define _SURE_POLICY_PARSER_H

#include <stdbool.h>

int sure_policy_run_file(const char *filepath, bool apply_to_kernel);

#endif
