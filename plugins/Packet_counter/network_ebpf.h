/*******************************************************
 Copyright (C) 2018-2023 Georges Da Costa <georges.da-costa@irit.fr>

    This file is part of Mojitos.

    Mojitos is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Mojitos is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MojitO/S.  If not, see <https://www.gnu.org/licenses/>.

 *******************************************************/


#define ERROR_LOAD_PROG -1
#define ERROR_OPEN_PROG -2
#define ERROR_CREATE_HOOK -3
#define ERROR_GET_ITF -4
#define ERROR_MODIFY_MAP -5
#define ERROR_GET_ID -6
#define ERROR_UPDATE_ELEM -7
#define ERROR_ACCESS_ELEM -8



unsigned int init_network(char *, void **);
unsigned int get_network(uint64_t *results, void *);
void clean_network(void *);
void label_network(char **labels, void *);


struct compteur_pckt {
	uint64_t data[3];
    
};

typedef struct compteur_pckt cpt_pckt;

/*Sensor network = {
    .init = init_network,
    .get = get_network,
    .clean = clean_network,
    .label = label_network,
    .nb_opt = 1,
};

Optparse network_opt[1] = {
    {
        .longname = "net-dev",
        .shortname = 'd',
        .argtype = OPTPARSE_REQUIRED,
        .usage_arg = "<net_dev>",
        .usage_msg = "network monitoring (if network_device is X, tries to detect it automatically)",
    },
};*/
