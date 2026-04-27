<?php

namespace Stackshield\Scanner\Reporters;

use Stackshield\Scanner\Finding;
use Stackshield\Scanner\Report;
use Stackshield\Scanner\Scanner;

final class SarifReporter implements Reporter
{
    public function render(Report $report): string
    {
        $rules = [];
        $results = [];
        $ruleIndex = [];

        foreach ($report->findings() as $finding) {
            if (! isset($ruleIndex[$finding->checkId])) {
                $ruleIndex[$finding->checkId] = count($rules);
                $rules[] = [
                    'id' => $finding->checkId,
                    'name' => $finding->checkName,
                    'shortDescription' => [
                        'text' => $finding->checkName,
                    ],
                    'defaultConfiguration' => [
                        'level' => $finding->severity->sarifLevel(),
                    ],
                    'properties' => [
                        'tags' => ['security', $finding->category->value],
                    ],
                ];
            }

            $result = [
                'ruleId' => $finding->checkId,
                'ruleIndex' => $ruleIndex[$finding->checkId],
                'level' => $finding->severity->sarifLevel(),
                'message' => [
                    'text' => $finding->message,
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $finding->file,
                                'uriBaseId' => '%SRCROOT%',
                            ],
                            'region' => [
                                'startLine' => max(1, $finding->line),
                            ],
                        ],
                    ],
                ],
                'partialFingerprints' => [
                    'stackshield/v1' => $finding->fingerprint,
                ],
            ];

            if ($finding->remediation) {
                $result['fixes'] = [
                    [
                        'description' => [
                            'text' => $finding->remediation,
                        ],
                    ],
                ];
            }

            $results[] = $result;
        }

        $sarif = [
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Stackshield Scanner',
                            'semanticVersion' => Scanner::VERSION,
                            'informationUri' => 'https://stackshield.io',
                            'rules' => $rules,
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];

        return json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
