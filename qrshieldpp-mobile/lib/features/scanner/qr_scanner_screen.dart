import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qrshieldpp_mobile/app/router/route_names.dart';
import 'package:qrshieldpp_mobile/features/verdict/risk_result_screen.dart';
import 'package:qrshieldpp_mobile/services/api_client/qrshield_api_client.dart';

class QRScannerScreen extends StatefulWidget {
  const QRScannerScreen({super.key});

  @override
  State<QRScannerScreen> createState() => _QRScannerScreenState();
}

class _QRScannerScreenState extends State<QRScannerScreen> {
  final MobileScannerController _scannerController = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );
  final QRShieldApiClient _apiClient = QRShieldApiClient();
  final TextEditingController _manualInputController = TextEditingController();

  bool _isProcessing = false;
  String? _lastContent;
  DateTime? _lastScanTime;
  String? _errorMessage;

  @override
  void dispose() {
    _manualInputController.dispose();
    _apiClient.dispose();
    _scannerController.dispose();
    super.dispose();
  }

  Future<void> _handleDetection(BarcodeCapture capture) async {
    if (_isProcessing) {
      return;
    }

    String? content;
    for (final barcode in capture.barcodes) {
      final value = barcode.rawValue?.trim();
      if (value != null && value.isNotEmpty) {
        content = value;
        break;
      }
    }

    if (content == null) {
      return;
    }

    final now = DateTime.now();
    if (_lastContent == content &&
        _lastScanTime != null &&
        now.difference(_lastScanTime!) < const Duration(seconds: 2)) {
      return;
    }
    _lastContent = content;
    _lastScanTime = now;

    await _submitQrContent(content);
  }

  Future<void> _submitQrContent(String content) async {
    if (_isProcessing) {
      return;
    }

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    await _scannerController.stop();

    try {
      final result = await _apiClient.scanQr(qrContent: content);
      if (!mounted) {
        return;
      }
      await Navigator.of(context).pushNamed(
        RouteNames.riskResult,
        arguments: RiskResultArgs(result: result),
      );
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _errorMessage = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
        await _scannerController.start();
      }
    }
  }

  Future<void> _onManualAnalyze() async {
    final input = _manualInputController.text.trim();
    if (input.isEmpty) {
      setState(() {
        _errorMessage = 'Enter URL or QR content to analyze.';
      });
      return;
    }
    await _submitQrContent(input);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('QRShield++ Scanner'),
      ),
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              child: Stack(
                fit: StackFit.expand,
                children: [
                  MobileScanner(
                    controller: _scannerController,
                    onDetect: _handleDetection,
                  ),
                  IgnorePointer(
                    child: Center(
                      child: Container(
                        width: 240,
                        height: 240,
                        decoration: BoxDecoration(
                          border: Border.all(
                            color: Colors.white.withOpacity(0.9),
                            width: 2,
                          ),
                          borderRadius: BorderRadius.circular(20),
                        ),
                      ),
                    ),
                  ),
                  if (_isProcessing)
                    ColoredBox(
                      color: Colors.black54,
                      child: Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: const [
                            CircularProgressIndicator(),
                            SizedBox(height: 12),
                            Text(
                              'Analyzing scan...',
                              style: TextStyle(color: Colors.white),
                            ),
                          ],
                        ),
                      ),
                    ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextField(
                    controller: _manualInputController,
                    enabled: !_isProcessing,
                    decoration: const InputDecoration(
                      labelText: 'Manual input (URL or QR text)',
                    ),
                  ),
                  const SizedBox(height: 8),
                  ElevatedButton(
                    onPressed: _isProcessing ? null : _onManualAnalyze,
                    child: const Text('Analyze Input'),
                  ),
                  if (_errorMessage != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      _errorMessage!,
                      style: const TextStyle(color: Colors.red),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
