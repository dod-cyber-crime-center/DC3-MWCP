"""
This serves as the STIX Report Writer.  This expands on the same report every time write is called.
A STIX package is generated and returned as a string when serialize is called
"""

from stix2 import v21 as stix
from stix2.v21 import _Observable

import mwcp
from mwcp import metadata
from mwcp.file_object import FileObject
from mwcp.report_writers import ReportWriter


class STIXWriter(ReportWriter):
    """
    Used to create a STIX Bundle that represents one or more MWCP Reports.
    Write must be called by each report that should be included in the final result.
    Serialize is called once this process is completed to return the STIX Bundle as a string.
    """
    def __init__(self, fixed_timestamp: str = None):
        # used to ensure we deduplicate objects prior to loading them into the bundle
        self._all_objects = {}
        # applies a fixed timestamp to all SDOs and SROs for their created and updated times
        self.fixed_timestamp = fixed_timestamp

    def write(self, report: metadata.Report):
        linked_ids = set()
        analysis_data = {
            "product": "mwcp",
            "version": mwcp.__version__,
            "result_name": report.parser,
            "allow_custom": True,
            "created": self.fixed_timestamp,
            "modified": self.fixed_timestamp
        }

        note_content = ["Description: " + str(report.input_file.description)]

        # we need to turn the FileObj into a metadata.File to fetch STIX content
        file_result = report.input_file.as_stix(None, self.fixed_timestamp)
        
        for item in file_result.linked_stix:
            self._add_stix_object(item)

        for item in file_result.unlinked_stix:
            self._add_stix_object(item)

        # the file should always be the first STIX object written
        base_file = file_result.linked_stix[0]

        analysis_data["sample_ref"] = base_file.id

        if file_result.note_content:
            note_content.append(file_result.note_content)

        for element in report.metadata:
            result = element.as_stix(base_file, self.fixed_timestamp)

            # Content is loaded to the master note for the File
            if result.note_content:
                note_content.append(result.note_content)

            # Linked items will be added the result set for the Malware Analysis
            for item in result.linked_stix:
                linked_ids.add(item.id)
                self._add_stix_object(item)

            # Unlinked items are added to the final result, but are not linked within the Malware Analysis.
            # Links should happen via relationships or embedded STIX relationships within the objects
            for item in result.unlinked_stix:
                self._add_stix_object(item)

        # make a single large Note for all Other data which was collected and not otherwise applied
        if len(note_content) > 0:
            note_params = {
                "content": "\n".join(note_content),
                "object_refs": [base_file.id],
                "created": self.fixed_timestamp,
                "modified": self.fixed_timestamp,
                "allow_custom": True
            }

            if len(file_result.note_labels) > 0:
                file_result.note_labels.sort()
                note_params["labels"] = file_result.note_labels

            note = stix.Note(**note_params)
            self._add_stix_object(note)

        # the malware analysis must be made last since we need the IDs for everything that came out of it
        if len(linked_ids) > 0:
            refs = list(linked_ids)
            refs.sort()
            analysis_data["analysis_sco_refs"] = refs
        else:
            analysis_data["result"] = "unknown"

        if report.tags:
            tags = list(report.tags)
            tags.sort()
            analysis_data["labels"] = tags
            
        malware_analysis = stix.MalwareAnalysis(**analysis_data)
        self._add_stix_object(malware_analysis)

    def serialize(self) -> str:
        # Consolidate Notes down to avoid needless duplication
        note_lookup = {}
        to_remove = []
        for idx, item in self._all_objects.items():
            if item.type == "note":
                if hasattr(item, "abstract"):
                    key = item.abstract + item.content
                else:
                    key = item.content

                if hasattr(item, "labels"):
                    key += " / ".join(item.labels)

                if key in note_lookup:
                    existing = note_lookup[key]
                    for ref in item.object_refs:
                        if ref not in existing.object_refs:
                            existing.object_refs.append(ref)
                    to_remove.append(idx)
                else:
                    note_lookup[key] = item

        # remove the duplicate notes
        # done outside of the initial loop to avoid messing with for
        for idx in to_remove:
            self._all_objects.pop(idx)

        values = self._all_objects.values()
        if len(values) > 0:
            package = stix.Bundle(objects=values, allow_custom=True)
        else:
            package = stix.Bundle()

        return package.serialize(indent=4)

    def _add_stix_object(self, stix_object: _Observable):
        """
        Adds a STIX object to the all objects dictionary and replaces the existing element if the new version has more details
        """
        if stix_object.id in self._all_objects:
            if len(stix_object.serialize()) > len(self._all_objects[stix_object.id].serialize()):
                self._all_objects[stix_object.id] = stix_object
        else:
            self._all_objects[stix_object.id] = stix_object
