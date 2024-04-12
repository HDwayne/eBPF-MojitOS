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

unsigned int init_mmap_ebpf(char *, void **);
unsigned int get_mmap_ebpf(uint64_t *results, void *);
void clean_mmap_ebpf(void *);
void label_mmap_ebpf(char **labels, void *);


Sensor mmap_ebpf = {
    .init = init_mmap_ebpf,
    .get = get_mmap_ebpf,
    .clean = clean_mmap_ebpf,
    .label = label_mmap_ebpf,
    .nb_opt = 1,
};

Optparse mmap_ebpf_opt[1] = {
    {
        .longname = "mmap_ebpf",
        .shortname = "P",
        .argtype = OPTPARSE_REQUIRED,
        .usage_arg = NULL,
        .usage_msg = "mmap values with eBPF\n",
    },
};