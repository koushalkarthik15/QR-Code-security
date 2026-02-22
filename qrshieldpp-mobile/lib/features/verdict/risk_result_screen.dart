import 'package:flutter/material.dart';
import 'package:qrshieldpp_mobile/app/router/route_names.dart';
import 'package:qrshieldpp_mobile/data/models/qrshield_models.dart';
import 'package:qrshieldpp_mobile/features/verdict/warning_gate_screen.dart';

class RiskResultArgs {
  RiskResultArgs({required this.result});

  final ScanQrResult result;
}

class RiskResultScreen extends StatelessWidget {
  const RiskResultScreen({required this.args, super.key});

  final RiskResultArgs args;

  @override
  Widget build(BuildContext context) {
    final result = args.result;
    final risk = result.risk;
    final score = risk.finalRiskScore0100;
    final label = risk.threatLabel;
    final scorePercent = (score / 100).clamp(0.0, 1.0);
    final color = _labelColor(label);
    final explanationText = result.explanation?.explanation.isNotEmpty == true
        ? result.explanation!.explanation
        : 'No explanation returned by backend.';

    return Scaffold(
      appBar: AppBar(
        title: const Text('Threat Assessment'),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Final Risk Score',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          '${score.toStringAsFixed(2)} / 100',
                          style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                                color: color,
                                fontWeight: FontWeight.bold,
                              ),
                        ),
                        const SizedBox(height: 8),
                        LinearProgressIndicator(
                          value: scorePercent,
                          minHeight: 10,
                          borderRadius: BorderRadius.circular(12),
                          color: color,
                        ),
                        const SizedBox(height: 10),
                        Chip(
                          label: Text(label),
                          side: BorderSide(color: color),
                          labelStyle: TextStyle(
                            color: color,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'Payload Type: ${result.payloadType}',
                          style: Theme.of(context).textTheme.bodyMedium,
                        ),
                        const SizedBox(height: 4),
                        Text(
                          'Payload: ${result.resolvedPayload}',
                          style: Theme.of(context).textTheme.bodyMedium,
                        ),
                        const SizedBox(height: 4),
                        Text(
                          'Recommended Action: ${result.recommendedAction.toUpperCase()}',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Threat Explanation',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Text(explanationText),
                      ],
                    ),
                  ),
                ),
                if ((result.explanation?.topContributors ?? const <TopContributor>[])
                    .isNotEmpty) ...[
                  const SizedBox(height: 12),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Top Contributors',
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          const SizedBox(height: 8),
                          ...result.explanation!.topContributors.take(3).map(
                                (item) => Padding(
                                  padding: const EdgeInsets.only(bottom: 8),
                                  child: Text(
                                    '- ${item.detail} '
                                    '(${(item.contribution01 * 100).toStringAsFixed(1)}%)',
                                  ),
                                ),
                              ),
                        ],
                      ),
                    ),
                  ),
                ],
                const SizedBox(height: 16),
                ElevatedButton(
                  onPressed: () {
                    Navigator.of(context).pushNamed(
                      RouteNames.warningGate,
                      arguments: WarningGateArgs(result: result),
                    );
                  },
                  child: const Text('Proceed (Warning Page)'),
                ),
                const SizedBox(height: 8),
                OutlinedButton(
                  onPressed: () {
                    Navigator.of(context).popUntil((route) => route.isFirst);
                  },
                  child: const Text('Block Link'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Color _labelColor(String label) {
    switch (label.toLowerCase()) {
      case 'safe':
        return Colors.green;
      case 'suspicious':
        return Colors.orange;
      case 'malicious':
        return Colors.red;
      default:
        return Colors.blueGrey;
    }
  }
}
