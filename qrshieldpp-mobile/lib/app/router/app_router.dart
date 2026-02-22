import 'package:flutter/material.dart';
import 'package:qrshieldpp_mobile/app/router/route_names.dart';
import 'package:qrshieldpp_mobile/app/theme/app_theme.dart';
import 'package:qrshieldpp_mobile/features/scanner/qr_scanner_screen.dart';
import 'package:qrshieldpp_mobile/features/verdict/risk_result_screen.dart';
import 'package:qrshieldpp_mobile/features/verdict/warning_gate_screen.dart';

class AppRouter {
  static Route<dynamic> onGenerateRoute(RouteSettings settings) {
    switch (settings.name) {
      case RouteNames.scanner:
        return MaterialPageRoute<void>(
          builder: (_) => const QRScannerScreen(),
          settings: settings,
        );

      case RouteNames.riskResult:
        final args = settings.arguments;
        if (args is RiskResultArgs) {
          return MaterialPageRoute<void>(
            builder: (_) => RiskResultScreen(args: args),
            settings: settings,
          );
        }
        return _errorRoute('Missing RiskResultArgs for /risk-result.');

      case RouteNames.warningGate:
        final args = settings.arguments;
        if (args is WarningGateArgs) {
          return MaterialPageRoute<void>(
            builder: (_) => WarningGateScreen(args: args),
            settings: settings,
          );
        }
        return _errorRoute('Missing WarningGateArgs for /warning-gate.');

      default:
        return _errorRoute('Unknown route: ${settings.name}');
    }
  }

  static Route<dynamic> _errorRoute(String message) {
    return MaterialPageRoute<void>(
      builder: (_) => Scaffold(
        appBar: AppBar(title: const Text('Routing Error')),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              message,
              textAlign: TextAlign.center,
            ),
          ),
        ),
      ),
    );
  }
}

class QRShieldMobileApp extends StatelessWidget {
  const QRShieldMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'QRShield++',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light(),
      initialRoute: RouteNames.scanner,
      onGenerateRoute: AppRouter.onGenerateRoute,
    );
  }
}
