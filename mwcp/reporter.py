"""
Interface for Reporter class. DEPRECATED
"""

import warnings

from mwcp.runner import Runner


def Reporter(
        outputdir=None,
        tempdir=None,
        disable_output_files=False,
        disable_temp_cleanup=False,
        base64_output_files=False,
        prefix_output_files=True,
    ):
    warnings.warn(
        "Reporter has been renamed to 'Runner', please either update the name or use "
        "the new mwcp.run() function.",
        DeprecationWarning
    )
    write_output_files = not disable_output_files
    # NOTE: Some argument names have been renamed and some have been inverted.
    # These were changed to fix the confusing double negatives or fix variables to use snake_case.
    return Runner(
        output_directory=outputdir if write_output_files else None,
        temp_directory=tempdir,
        cleanup_temp_files=not disable_temp_cleanup,
        include_file_data=base64_output_files,
        prefix_output_files=prefix_output_files,
    )
