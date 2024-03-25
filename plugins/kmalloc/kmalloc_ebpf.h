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

unsigned int init_kmalloc_ebpf(char *, void **);
unsigned int get_kmalloc_ebpf(uint64_t *results, void *);
void clean_kmalloc_ebpf(void *);
void label_kmalloc_ebpf(char **labels, void *);


Sensor kmalloc_ebpf = {
    .init = init_kmalloc_ebpf,
    .get = get_kmalloc_ebpf,
    .clean = clean_kmalloc_ebpf,
    .label = label_kmalloc_ebpf,
    .nb_opt = 1,
};

Optparse kmalloc_ebpf_opt[1] = {
    {
        .longname = "kmalloc_ebpf",
        .shortname = 'K',
        .argtype = OPTPARSE_REQUIRED,
        .usage_arg = "à déterminer",
        .usage_msg = "à déterminer",
    },
};