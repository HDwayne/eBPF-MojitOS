# eBPF-MojitOS
PLugin to implement EBPF on 

 il suffit de faire:

- make clean puis make 

- sudo ./packet_compteur [le type de flow ( ingress ou  egress ) ] [ la fréquence des prints en secondes ] [ le nom de l'interface réseau sur laquelle attacher le prog ] et hop ça affiche le résultat directement sur le terminal (à chaque seconde)

