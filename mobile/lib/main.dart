import 'package:flutter/material.dart';
import 'api.dart';

const apiBaseUrl = String.fromEnvironment('API_BASE_URL', defaultValue: 'http://10.0.2.2:8000');

void main() => runApp(const WorkPortalApp());

class WorkPortalApp extends StatelessWidget {
  const WorkPortalApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Рабочий портал',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.blueGrey),
      home: const AuthPage(),
    );
  }
}

class AuthPage extends StatefulWidget {
  const AuthPage({super.key});
  @override State<AuthPage> createState() => _AuthPageState();
}

class _AuthPageState extends State<AuthPage> {
  final api = ApiClient(baseUrl: apiBaseUrl);
  final loginUser = TextEditingController();
  final loginPass = TextEditingController();
  final invite = TextEditingController();
  final regUser = TextEditingController();
  final regPass = TextEditingController();
  bool registerMode = false;
  bool busy = false;
  String? error;

  Future<void> submit() async {
    setState(() { busy = true; error = null; });
    try {
      final user = registerMode
          ? await api.register(invite.text.trim(), regUser.text.trim(), regPass.text)
          : await api.login(loginUser.text.trim(), loginPass.text);
      if (mounted) Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => HomePage(api: api, user: user)));
    } catch (e) { if (mounted) setState(() => error = e.toString().replaceFirst('Exception: ', '')); }
    if (mounted) setState(() => busy = false);
  }

  InputDecoration d(String label) => InputDecoration(labelText: label, border: const OutlineInputBorder());
  @override
  Widget build(BuildContext context) => Scaffold(
    body: SafeArea(child: Center(child: SingleChildScrollView(padding: const EdgeInsets.all(22), child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 460),
      child: Card(child: Padding(padding: const EdgeInsets.all(22), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        const Text('Рабочий портал', style: TextStyle(fontSize: 28, fontWeight: FontWeight.w800)),
        const SizedBox(height: 18),
        SegmentedButton<bool>(segments: const [ButtonSegment(value: false, label: Text('Вход')), ButtonSegment(value: true, label: Text('Регистрация'))], selected: {registerMode}, onSelectionChanged: (v) => setState(() => registerMode = v.first)),
        const SizedBox(height: 18),
        if (registerMode) ...[
          TextField(controller: invite, decoration: d('Ключ приглашения')),
          const SizedBox(height: 12),
          TextField(controller: regUser, decoration: d('Логин')),
          const SizedBox(height: 12),
          TextField(controller: regPass, obscureText: true, decoration: d('Пароль')),
        ] else ...[
          TextField(controller: loginUser, decoration: d('Логин')),
          const SizedBox(height: 12),
          TextField(controller: loginPass, obscureText: true, decoration: d('Пароль')),
        ],
        const SizedBox(height: 16),
        if (error != null) Padding(padding: const EdgeInsets.only(bottom: 10), child: Text(error!, style: const TextStyle(color: Colors.red))),
        FilledButton(onPressed: busy ? null : submit, child: Text(busy ? 'Подождите…' : registerMode ? 'Создать аккаунт' : 'Войти')),
      ]))),
    ))),
  );
}

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.api, required this.user});
  final ApiClient api; final Map<String, dynamic> user;
  @override State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  late Map<String, dynamic> user = widget.user;
  bool ownerBusy = false;
  String? lastInvite;
  String role = 'worker';

  Future<void> generateInvite() async {
    setState(() => ownerBusy = true);
    try { final d = await widget.api.createInvite(role); if (mounted) setState(() => lastInvite = d['code'] as String); }
    catch (e) { if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.toString()))); }
    if (mounted) setState(() => ownerBusy = false);
  }

  Future<void> logout() async { await widget.api.logout(); if (mounted) Navigator.of(context).pushAndRemoveUntil(MaterialPageRoute(builder: (_) => const AuthPage()), (_) => false); }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Рабочий портал'), actions: [IconButton(onPressed: logout, icon: const Icon(Icons.logout))]),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      Card(child: ListTile(leading: const CircleAvatar(child: Icon(Icons.person)), title: Text(user['username'] as String), subtitle: Text('Роль: ${user['role']}'))),
      const SizedBox(height: 12),
      Card(child: ListTile(leading: const Icon(Icons.assignment), title: const Text('Рабочие данные'), subtitle: const Text('Разделы производства будут подключены к общему API.'))),
      Card(child: ListTile(leading: const Icon(Icons.manage_accounts), title: const Text('Настройки аккаунта'), onTap: () => showAccountSettings(context))),
      if (user['role'] == 'owner') ...[
        const SizedBox(height: 8),
        Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const Text('Панель владельца', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(value: role, decoration: const InputDecoration(labelText: 'Роль ключа', border: OutlineInputBorder()), items: const [DropdownMenuItem(value: 'worker', child: Text('Работник')), DropdownMenuItem(value: 'manager', child: Text('Руководитель')), DropdownMenuItem(value: 'admin', child: Text('Администратор'))], onChanged: (v) => setState(() => role = v ?? 'worker')),
          const SizedBox(height: 12),
          FilledButton.icon(onPressed: ownerBusy ? null : generateInvite, icon: const Icon(Icons.key), label: Text(ownerBusy ? 'Генерируется…' : 'Сгенерировать ключ')),
          if (lastInvite != null) Padding(padding: const EdgeInsets.only(top: 14), child: SelectableText(lastInvite!, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w800, letterSpacing: 2))),
        ]))),
      ],
    ]),
  );

  Future<void> showAccountSettings(BuildContext context) async {
    final userCtl = TextEditingController(text: user['username'] as String);
    final currentCtl = TextEditingController(); final newPassCtl = TextEditingController();
    await showModalBottomSheet<void>(context: context, isScrollControlled: true, builder: (sheet) => Padding(
      padding: EdgeInsets.fromLTRB(20, 20, 20, MediaQuery.of(sheet).viewInsets.bottom + 20),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Text('Настройки аккаунта', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        TextField(controller: userCtl, decoration: const InputDecoration(labelText: 'Новый логин', border: OutlineInputBorder())),
        const SizedBox(height: 8),
        TextField(controller: currentCtl, obscureText: true, decoration: const InputDecoration(labelText: 'Текущий пароль', border: OutlineInputBorder())),
        const SizedBox(height: 8),
        TextField(controller: newPassCtl, obscureText: true, decoration: const InputDecoration(labelText: 'Новый пароль (для смены)', border: OutlineInputBorder())),
        const SizedBox(height: 12),
        FilledButton(onPressed: () async { try { await widget.api.changeUsername(userCtl.text.trim(), currentCtl.text); if (newPassCtl.text.isNotEmpty) await widget.api.changePassword(currentCtl.text, newPassCtl.text); if (mounted) { Navigator.pop(sheet); ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Изменения сохранены'))); if (newPassCtl.text.isNotEmpty) await logout(); }} catch (e) { if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.toString()))); } }, child: const Text('Сохранить')),
      ]),
    ));
  }
}
