rule GenericVOneRule
{
	meta:
		description = "Generic Yara rule to detect Azorult cookie victim files"
		author = "FH"
		date = "2025-01-27"
		version = "1.0"
		mwcp = "CookieFinder.GenericVOne"

	strings:
		$regex = /^[^\s]+\x09(TRUE|FALSE)\x09\x2F\x09(TRUE|FALSE)\x09[123]\d{9}\x09[^$]+$/
	condition:
		$regex
}
