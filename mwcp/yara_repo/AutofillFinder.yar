rule GenericVOneRule
{
	meta:
		description = "Generic Yara rule to detect Autofill data"
		author = "FH"
		date = "2025-01-27"
		version = "1.0"
		mwcp = "AutofillFinder.GenericVOne"

	strings:
		$firstname="firstname" ascii wide nocase
		$lastname="lastname" ascii wide nocase
		$applica="applica" ascii wide nocase
		$email = "email" ascii wide nocase
		$address = "address" ascii wide nocase
		$special = /email\]?:\s*[^\n]+[$\n]/

	condition:
		$firstname and $lastname and ($applica or $email or $address) and #special>10
}
