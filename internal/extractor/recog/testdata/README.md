# Recog fixtures

`snapshot/xml/` holds real fingerprints from https://github.com/rapid7/recog at
revision `f1191e24332c51d6a3d98457f64fba8dec340784`, copied unmodified (a
subset of the elements of each file, with the original file headers). They
cover each file the extractor reads, fingerprints with literal and captured
versions, certainty, CPE values, and entries the extractor must skip
(operating-system-only entries and a dynamic product).

Recog is under the BSD 2-Clause license, Copyright 2014 Rapid7, Inc.
(`debian/copyright` of the repository). The copyright notice and license text
must be kept when redistributing these files.

Do not use these files to infer upstream coverage.
