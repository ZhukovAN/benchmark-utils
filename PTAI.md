# Positive Technologies Application Inspector (PT AI) SARIF report support
## Build
BenchmarkUtils source code includes locale-specific JUnit tests that fail in some environments like Russian. So we need to disable JUnit testing during build:
``` bash
mvn clean install -DskipTests=true
```
## Create PT AI report template
Out of the box PT AI SARIF report lacks CWE information so we need to create new report template:
```
{{
func mapLevel(level)
  case level
    when 'level-high'
      ret 'error'
    when 'level-medium'
      ret 'warning'
    else
      ret 'note'
  end
end

func removeLineNumber(uri)
  # some filenames also include line number at the end like this: 'file.txt : 123', so removing it
  ret regex.replace(uri, "\\s?:\\s?\\d+", "")
end

func extractDataFlowLocation(lines) # returns { line: number, snippet: string }
  for line in lines
    if line.Type == 'separator'
      continue
    end

    for codeLine in line.CodeLines
      if codeLine.PartType != 'Code'
        ret {
          line: line.LineNumber,
          snippet: codeLine.CodeLinePart
        }
      end
    end
  end

  ret {
    line: lines[0].LineNumber,
    snippet: lines[0].CodeLines[0].CodeLinePart,
  }
end

func collectRules(vulns) # returns { id, level, name, markdown }[]

    result = {}

    for vuln in vulns
        typeId = vuln.Type.Id

        if result[typeId]
            continue
        end

        result[typeId] = {
            id: typeId,
            name: vuln.Type.DisplayName,
            level: mapLevel(vuln.Level.Value)
        }

        if vuln.CweId
            result[typeId].cweId = vuln.CweId
        end

        for cve in vuln.CveDescriptions
            result[vuln.Type.Id].markdown += cve.Key + "\n" + cve.Description + "\n\n"
        end
    end

    # merge with full descriptions if they exist
    for term in GlossaryItems | array.compact
        desc = result[term.TypeId]
        desc.name = term.DisplayName
        desc.html = term.Value
        desc.markdown = term.ValueMarkdown
    end

    ret object.values(result)
end

func collectSuppressions(vuln) # returns { kind, status }[]

    result = []

    if vuln.IsSuppressed
        result = array.add(result, { "kind": "inSource", "status": "accepted" })
    end

    if vuln.ApprovalState == 'Discard'
        result = array.add(result, { "kind": "external", "status": "accepted" })
    end

    if vuln.ApprovalState == 'Approval'
        result = array.add(result, { "kind": "external", "status": "rejected" })
    end

    if vuln.ApprovalState == 'AutoApproval'
        result = array.add(result, { "kind": "external", "status": "rejected", "justification": "Autoconfirmed" })
    end

    ret result
end

func vulnCode(vuln)
    if !string.empty(vuln.VulnerableCode)
        ret vuln.VulnerableCode
    end

    if !string.empty(vuln.MatchedCode)
        ret removeLineNumber(vuln.MatchedCode)
    end

    ret null
end

func lineNumber(vuln)
    if vuln.BeginLine > 0
        ret vuln.BeginLine
    end

    if vuln.NumberLine > 0
        ret vuln.NumberLine
    end

    ret null
end

-}}

{
  "version": "2.1.0",
  "$schema": "http://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Positive Technologies Application Inspector",
          {{- findVersion(item) = item.Order == 4
          version = ScanInfo.Settings | array.filter @findVersion | array.first }}
          "version": "{{ version.Value }}",
          "organization": "Positive Technologies",
          "informationUri": "https://www.ptsecurity.com/ww-en/products/ai/",
          "rules": [
            {{- for rule in collectRules(Items) }}
            {
              "id": "{{ rule.id }}",
              "name": "{{ rule.name | string.escape }}",
              "properties": {
                {{- if rule.cweId }}
                "cwe": [
                  "CWE-{{ rule.cweId }}"
                ]
                {{- end }}
              },
              {{- if rule.markdown }}
              "fullDescription": {
                "text": "{{ rule.html | string.escape }}",
                "markdown": "{{ rule.markdown | string.escape }}"
              },
              {{- end }}
              "defaultConfiguration": {
                "level": "{{ rule.level }}",
                "enabled": true
              },
              "messageStrings": {
                "default": {
                  "text": "{{ rule.name | string.escape }}"
                }
              }
            }{{- if !for.last -}},{{ end }}
            {{- end }}
          ]
        }
      },
      "results": [
        {{- for vuln in Items }}
        {
          "ruleId": "{{ vuln.Type.Id }}",
          {{- suppressions = collectSuppressions(vuln) }}
          "suppressions": [
            {{- for sup in suppressions }}
            {
              "kind": "{{ sup.kind }}",
              "status": "{{ sup.status }}"
              {{- if sup.justification }},
              "justification": "{{ sup.justification }}"
              {{- end }}
            }{{- if !for.last -}},{{ end }}
            {{- end }}
          ],
          "message": {
            "id": "default",
            "text": "{{ vuln.Type.DisplayName }}"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "{{ vuln.SourceFile | removeLineNumber | string.escape }}"
                }
                {{- if lineNumber(vuln) || !string.empty(vulnCode(vuln)) }}
                ,
                "region": {
                  {{- if lineNumber(vuln) }}
                  "startLine": {{ lineNumber(vuln) }}
                  {{- end }}
                  {{- if !string.empty(vulnCode(vuln)) }}
                  {{- if lineNumber(vuln) }},{{- end }}
                  "snippet": {
                    "text": "{{ vulnCode(vuln) | string.escape }}"
                  }
                  {{- end }}
                }
                {{- end }}
              }
            }
          ]
          {{- if vuln.DataFlowElements | array.size > 0 -}}
          ,
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {{- for dataFlowItem in vuln.DataFlowElements }}
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": "{{ dataFlowItem.FullPath | removeLineNumber | string.escape }}"
                          },
                          {{- location = dataFlowItem.Lines | extractDataFlowLocation }}
                          "region": {
                            "startLine": {{ location.line }},
                            "snippet": {
                              "text": "{{ location.snippet | string.escape }}"
                            }
                          }
                        },
                        "message": {
                          "text": "{{ dataFlowItem.EntryTypeDisplayValue }}"
                        }
                      }
                    }{{- if !for.last -}},{{ end }}
                    {{- end }}
                  ]
                }
              ]
            }
          ]
          {{- end }}
        }{{- if !for.last -}},{{ end }}
        {{- end }}
      ]
    }
  ]
}
```
## Usage
Scan [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava.git) project and generate PT AI report using custom report template. Copy report into local OWASP Benchmark `results` folder and run `createScorecards.bat` script. Resulting scorecards will be generated in `C:\DATA\DEVEL\JAVA\BenchmarkJava\scorecard` folder  