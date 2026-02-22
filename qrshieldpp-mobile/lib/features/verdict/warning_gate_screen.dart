import 'package:flutter/material.dart';
import 'package:qrshieldpp_mobile/data/models/qrshield_models.dart';
import 'package:url_launcher/url_launcher.dart';

class WarningGateArgs {
  WarningGateArgs({required this.result});

  final ScanQrResult result;
}

class WarningGateScreen extends StatefulWidget {
  const WarningGateScreen({required this.args, super.key});

  final WarningGateArgs args;

  @override
  State<WarningGateScreen> createState() => _WarningGateScreenState();
}

class _WarningGateScreenState extends State<WarningGateScreen> {
  bool _isOpening = false;
  String? _openError;

  @override
  Widget build(BuildContext context) {
    final result = widget.args.result;
    final risk = result.risk;
    final color = _labelColor(risk.threatLabel);

    return Scaffold(
      appBar: AppBar(title: const Text('Safety Warning')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.warning_amber_rounded, color: color),
                          const SizedBox(width: 8),
                          Text(
                            '${risk.threatLabel} (${risk.finalRiskScore0100.toStringAsFixed(2)}/100)',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: color,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      const Text('This payload may be unsafe.'),
                      const SizedBox(height: 6),
                      Text(
                        result.resolvedPayload,
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        result.explanation?.explanation.isNotEmpty == true
                            ? result.explanation!.explanation
                            : 'Proceed only if you trust this source.',
                      ),
                    ],
                  ),
                ),
              ),
              const Spacer(),
              ElevatedButton(
                onPressed: _isOpening ? null : _openPayload,
                child: _isOpening
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Continue Anyway'),
              ),
              const SizedBox(height: 8),
              OutlinedButton(
                onPressed: _isOpening
                    ? null
                    : () => Navigator.of(context).popUntil((route) => route.isFirst),
                child: const Text('Block and Return'),
              ),
              if (_openError != null) ...[
                const SizedBox(height: 8),
                Text(
                  _openError!,
                  style: const TextStyle(color: Colors.red),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _openPayload() async {
    setState(() {
      _isOpening = true;
      _openError = null;
    });

    try {
      final rawPayload = widget.args.result.resolvedPayload.trim().isNotEmpty
          ? widget.args.result.resolvedPayload.trim()
          : widget.args.result.qrContent.trim();
      if (rawPayload.isEmpty) {
        throw const FormatException('Payload is empty.');
      }

      final hasScheme = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*:').hasMatch(rawPayload);
      final normalized = hasScheme ? rawPayload : 'https://$rawPayload';
      final uri = Uri.tryParse(normalized);

      if (uri == null) {
        throw const FormatException('Invalid payload format.');
      }

      final allowedSchemes = <String>{'http', 'https', 'upi', 'tel', 'sms'};
      final scheme = uri.scheme.toLowerCase();
      if (!allowedSchemes.contains(scheme)) {
        throw FormatException('Unsupported payload scheme: $scheme');
      }

      if ((scheme == 'http' || scheme == 'https') && uri.host.trim().isEmpty) {
        throw const FormatException('URL host is empty.');
      }

      final launched = await launchUrl(uri, mode: LaunchMode.externalApplication);
      if (!launched) {
        throw const FormatException('Could not open payload in an external application.');
      }
    } catch (error) {
      setState(() {
        _openError = error.toString();
      });
      return;
    } finally {
      if (mounted) {
        setState(() {
          _isOpening = false;
        });
      }
    }

    if (mounted) {
      Navigator.of(context).popUntil((route) => route.isFirst);
    }
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
