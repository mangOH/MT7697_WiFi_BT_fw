#include "swi_messaging.h"


int swi_process_cmd(swi_m2s_info_t* m2s_info, const struct mt7697_command_entry cmd_defs[],
                    size_t num_cmd_defs, mt7697_cmd_hdr_t *cmd)
{
    int ret;
    for (int i = 0; i < num_cmd_defs; i++)
    {
        if (cmd_defs[i].enum_value == cmd->type)
        {
	        bool valid_length = false;
	        switch (cmd_defs[i].command_size_validator.type)
	        {
	        case CMD_SIZE_VALIDATOR_ABSOLUTE:
		        valid_length = (cmd->len == cmd_defs[i].command_size_validator.v.expected_size);
		        break;

	        case CMD_SIZE_VALIDATOR_FUNCTION:
		        valid_length = cmd_defs[i].command_size_validator.v.is_valid_size(cmd);
		        break;
	        }

            if (!valid_length)
            {
                LOG_E(common, "Received %s with invalid length=%d", cmd_defs[i].enum_name,
                      cmd->len);
                ret = -1;
            }
            else
            {
                ret = cmd_defs[i].command_handler(m2s_info, cmd);
                if (ret != 0)
                {
                    LOG_W(common, "Processing of %s in %s failed with return code %d",
                          cmd_defs[i].enum_name, cmd_defs[i].command_handler_name, ret);
                }
            }
            goto done;
        }
    }

    LOG_E(common, "No command handler registered for type=%d", cmd->type);
    ret = -1;

done:
    return ret;
}
