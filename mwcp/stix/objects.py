"""
This provides helper objects that can be used to generate STIX content
"""


class STIXResult:
    """
    Provides a means to return STIX 2.1 content

    :var linked_stix: An array of STIX objects that should be linked to a parent malware analysis object
    :var unlinked_stix: An array of STIX objects that should not be linked to a parent malware analysis object.
         This can include relationship objects, objects connected by relationship objects,
         and objects with embedded references like Notes
    :var note_content: The content of the note which will be attached to the STIX file object being analyzed by the
        malware analysis
    :var note_labels: The labels of the note which will be attached to the STIX file object being analyzed by the
        malware analysis
    """

    def __init__(self, note_content: str = "", fixed_timestamp: str = None):
        self.linked_stix = []
        self.unlinked_stix = []
        self.note_content = note_content
        self.note_labels = []
        self.fixed_timestamp = fixed_timestamp

    def add_linked(self, stix_content):
        self.linked_stix.append(stix_content)

    def add_unlinked(self, stix_content):
        self.unlinked_stix.append(stix_content)

    def create_tag_note(self, metadata, stix_content):
        note = metadata.as_stix_tags(stix_content, self.fixed_timestamp)
        if note:
            self.unlinked_stix.append(note)

    def merge(self, other):
        self.linked_stix.extend(other.linked_stix)
        self.unlinked_stix.extend(other.unlinked_stix)

        if self.note_content == "":
            self.note_content = other.note_content
        elif other.note_content != "":
            self.note_content += "\n" + other.note_content