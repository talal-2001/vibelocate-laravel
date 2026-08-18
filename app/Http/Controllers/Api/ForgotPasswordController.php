<?php

namespace App\Http\Controllers\Api;

use App\Services\Auth\JwtService;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ForgotPasswordController extends Controller
{
    public function __construct(private JwtService $jwt) {}

    public function __invoke(Request $request)
    {
        $email = strtolower(trim((string) $request->input('email', '')));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['success' => false, 'message' => 'Invalid email address'], 422);
        }

        $user = DB::table('users')->where('email', $email)->whereNull('deleted_at')->select('id')->first();
        $response = ['success' => true, 'message' => 'If the email exists, a reset token was created'];

        if ($user) {
            DB::table('password_resets')->where('email', $email)->delete();
            $token = $this->jwt->emailToken();
            DB::table('password_resets')->insert([
                'email' => $email,
                'token' => $token,
                'expires_at' => now()->addHour(),
            ]);
            if (app()->environment('local')) $response['reset_token'] = $token;
        }

        return response()->json($response);
    }
}
