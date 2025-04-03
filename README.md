# IDEA
Create a tool and manual for hunting vulnerabilities in C-Family software.  

# WHY THREE TOOLS?
* `Semgrep` - for static analysis when target <b>cannot be compiled</b>.
* `CodeQL` - for taint analysis when target <b>can be compiled</b>.
* `angr` - for symbolic execution when target <b>can be run</b>.

# HOW TO USE
I am trying to develop three set of the `rules` for the same vulnerability in parallel:
* `semgrep_rules` - rules for semgrep - target cannot be compiled
* `codeql_rules` - rules for codeql - target can be compiled
* `angr_rules` - rules for angr - target can be run

Rules in "not_my_rules" directory are from:
* 0xdea I forked them [here](https://github.com/Karmaz95/semgrep-rules).

## SEMGREP
```sh
semgrep -c rules/semgrep_rules/sprintf-buffer-overflow.yaml samples/CVE-2021-20294/readelf.c
```

## CODEQL
```sh
# Go to target build directory
cd samples/TARGET_BUILD_DIR
# Create codeql database
codeql database create /Users/karmaz/r/scripts/FUZZER/STATIC_HUNTER/tmp/MY_PROJECT-db --language=cpp --command="bash -c \"./configure && make\""
# Go back to root directory
cd ../../../
# Run query
codeql query run rules/codeql_rules/sprintf-overflow.ql --database=tmp/MY_PROJECT-db
```

## ANGR
```sh
python3 rules/angr_rules/angr_sprintf-overflow.py "./vulnerable_binary -arg1 test -arg2 123"
```
These rules can be imported into a larger tool and used to find vulnerabilities in binaries.
```python
from angr_sprintf_overflow import find_sprintf_overflow
find_sprintf_overflow("readelf")
```

# SAMPLES 
I started building this tool while learning [Vulnerabilities 1001: C-Family Software Implementation Vulnerabilities](https://apps.p.ost2.fyi/learning/course/course-v1:OpenSecurityTraining2+Vulns1001_C-family+2023_v1/home) from [OpenSecurityTraining2](https://p.ost2.fyi/) course. First CVEs in `samples` directory comes from the course. They are categorized by the CVE numbers and pseudo.c most of the time is copy-pasted from the course.
