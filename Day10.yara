//Added to Day3 Ruleset
import "time"

rule TTP_Tampered_Time_Stamp {
    meta:
        author = "RustyNoob619"
        description = "Detects PE files that have time stamps from the future"

    condition:
        pe.timestamp > time.now()
}
