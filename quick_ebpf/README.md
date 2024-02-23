# Structure du Projet

```
quick_ebpf/
│
├── ebpf_programs/                 # Dossier contenant des exemples de blocs eBPF
│   ├── cpu_usage.bpf.c     # Surveille les commutations de contexte par PID
│   └── disk_activity.bpf.c # Surveille les écritures sur disque par PID
│
├── lib/                    # Bibliothèque eBPF générique
│   ├── ebpf_lib.h          # En-têtes pour la bibliothèque générique eBPF
│   └── ebpf_lib.c          # Implémentation de la bibliothèque générique eBPF
│
├── Makefile                # Makefile pour compiler le projet
│
└── main.c                  # Programme principal en C

```

# Description des Composants

- ebpf_programs/ : Contient les programmes eBPF individuels. Chaque fichier .bpf.c représente un programme eBPF conçu pour une tâche de surveillance spécifique.

- lib/ : Fournit une bibliothèque générique pour faciliter le chargement et l'attachement des programmes eBPF, ainsi que la manipulation des maps eBPF depuis l'espace utilisateur.

- Makefile : Permet de compiler facilement le projet, y compris les programmes eBPF et le programme utilisateur.

- main.c : Le programme utilisateur qui initialise l'environnement eBPF, charge et attache les programmes eBPF, et effectue la surveillance basée sur les données collectées par les programmes eBPF.


# Configuration Requise

- Fichiers Blocs eBPF : Modifiez le chemin du fichier dans main.c pour pointer vers le bon fichier .bpf.o compilé correspondant à votre bloc eBPF.

- Maps eBPF : Assurez-vous que le nom de la map utilisée dans main.c correspond exactement au nom de la map définie dans votre programme eBPF.