import "vt"

rule VT_MAL_WIN_EXE_Ransomware_NailaoLocker_mutex_FEB25 {

  meta:
    description = "Detects Nailaolocker Ransomware based on the mutex"
    author = "RustyNoob"
    source = "https://www.orangecyberdefense.com/global/blog/cert-news/meet-nailaolocker-a-ransomware-distributed-in-europe-by-shadowpad-and-plugx-backdoors"
    file_hash = "e0d89af13acb3e3433f6923f09d4a1586815afbb6b6a01ae32da74dc81f43a99"

  condition:
    for any mutex in vt.behaviour.mutexes_created : (
       mutex == "Global\\lockv7"
    )
}
