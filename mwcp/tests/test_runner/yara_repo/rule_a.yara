
rule Rule_Mapped {
    meta:
        mwcp = "dc3:foo"
    strings:
        $str = "mapped"
    condition:
        all of them
}

rule Rule_Unmapped {
    strings:
        $str = "unmapped"
    condition:
        all of them
}
