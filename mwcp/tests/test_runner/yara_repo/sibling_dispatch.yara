/*
Rules for test_yara_runner_sibling_dispatch
*/

rule Parent {
    meta:
        mwcp = "SiblingDispatch.Parent"
    strings:
        $str = "parent"
    condition:
        all of them
}


rule Sibling1 {
    meta:
        mwcp = "SiblingDispatch.Sibling1"
    strings:
        $str = "sibling 1"
    condition:
        all of them
}


rule Sibling2 {
    meta:
        mwcp = "SiblingDispatch.Sibling2"
    strings:
        $str = "sibling 2"
    condition:
        all of them
}


rule Grandchild {
    meta:
        mwcp = "SiblingDispatch.Grandchild"
    strings:
        $str = "grandchild"
    condition:
        all of them
}
