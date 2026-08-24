import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class ApiClient {
  ApiClient({required this.baseUrl});
  final String baseUrl;

  Future<Map<String, String>> _headers() async {
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString('token');
    return {
      'Content-Type': 'application/json',
      if (token != null && token.isNotEmpty) 'Authorization': 'Bearer $token',
    };
  }

  Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Map<String, dynamic>? body,
  }) async {
    final uri = Uri.parse('$baseUrl$path');
    final headers = await _headers();
    late http.Response response;
    if (method == 'GET') {
      response = await http.get(uri, headers: headers);
    } else if (method == 'POST') {
      response = await http.post(uri, headers: headers, body: jsonEncode(body ?? {}));
    } else if (method == 'PUT') {
      response = await http.put(uri, headers: headers, body: jsonEncode(body ?? {}));
    } else {
      throw Exception('Unsupported HTTP method');
    }
    final data = response.body.isEmpty ? <String, dynamic>{} : jsonDecode(response.body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception(data is Map && data['detail'] != null ? data['detail'] : 'Ошибка сервера');
    }
    return Map<String, dynamic>.from(data as Map);
  }

  Future<Map<String, dynamic>> login(String username, String password) async {
    final data = await _request('POST', '/api/login', body: {'username': username, 'password': password});
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', data['access_token'] as String);
    return Map<String, dynamic>.from(data['user'] as Map);
  }

  Future<Map<String, dynamic>> register(String invite, String username, String password) async {
    final data = await _request('POST', '/api/register', body: {
      'invite_code': invite,
      'username': username,
      'password': password,
    });
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', data['access_token'] as String);
    return {'id': data['id'], 'username': data['username'], 'role': data['role']};
  }

  Future<Map<String, dynamic>> me() => _request('GET', '/api/me');

  Future<void> logout() async {
    try { await _request('POST', '/api/logout'); } finally {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove('token');
    }
  }

  Future<void> changeUsername(String username, String password) async {
    await _request('PUT', '/api/me/username', body: {
      'new_username': username,
      'current_password': password,
    });
  }

  Future<void> changePassword(String currentPassword, String newPassword) async {
    await _request('PUT', '/api/me/password', body: {
      'current_password': currentPassword,
      'new_password': newPassword,
    });
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
  }

  Future<List<dynamic>> invites() async {
    final data = await _request('GET', '/api/invites');
    return data is List ? data : <dynamic>[];
  }

  Future<Map<String, dynamic>> createInvite(String role) =>
      _request('POST', '/api/invites', body: {'role': role});

  Future<List<dynamic>> users() async {
    final data = await _request('GET', '/api/admin/users');
    return data is List ? data : <dynamic>[];
  }
}
