#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "lib/stringinfo.h"
#include <stdio.h>
#include <stdlib.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(sys_exec);
Datum sys_exec(PG_FUNCTION_ARGS)
{
    char *cmd = text_to_cstring(PG_GETARG_TEXT_PP(0));
    PG_RETURN_INT32(system(cmd));
}

PG_FUNCTION_INFO_V1(sys_eval);
Datum sys_eval(PG_FUNCTION_ARGS)
{
    char *cmd = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char line[1024];
    StringInfoData out;
    FILE *p = popen(cmd, "r");

    initStringInfo(&out);
    if (p) {
        while (fgets(line, sizeof line, p))
            appendStringInfoString(&out, line);
        pclose(p);
    }
    PG_RETURN_TEXT_P(cstring_to_text(out.data));
}
