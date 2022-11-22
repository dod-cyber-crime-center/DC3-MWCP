
rule FileA {
    meta:
        mwcp = "Sample.FileA"
    strings:
        $str = "file a"
    condition:
        all of them
}


rule FileB {
    meta:
        mwcp = "Sample.FileB"
    strings:
        $str = "file b"
    condition:
        all of them
}

