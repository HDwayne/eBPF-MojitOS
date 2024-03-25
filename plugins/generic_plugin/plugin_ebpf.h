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

/* This code has to be included to ../src/
 Define every type of error here*/

unsigned int init_plugin_ebpf(char *, void **);
unsigned int get_plugin_ebpf(uint64_t *results, void *);
void clean_plugin_ebpf(void *);
void label_plugin_ebpf(char **labels, void *);


Sensor plugin_ebpf = {
    .init = init_plugin_ebpf,
    .get = get_plugin_ebpf,
    .clean = clean_plugin_ebpf,
    .label = label_plugin_ebpf,
    .nb_opt = 1,
};

Optparse kmalloc_ebpf_opt[1] = {
    {
        .longname = "plugin_ebpf",
        .shortname = /*define a letter to you plugin (str)*/,
        .argtype = OPTPARSE_REQUIRED,
        .usage_arg = "à déterminer",
        .usage_msg = /*define a message print to describe briefly your plugin (str)*/,
    },
};