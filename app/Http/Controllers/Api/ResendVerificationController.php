<?php

namespace App\Http\Controllers\Api;

use App\Services\Auth\JwtService;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ResendVerificationController extends Controller
{
    public function __construct(private JwtService $jwt) {}

    public function __invoke(Request $request)
    {
        $email = strtolower(trim((string) $request->input('email', '')));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['success' => false, 'message' => 'Invalid email address'], 422);
        }

        $user = DB::table('users')->where('email', $email)->whereNull('deleted_at')->select('id', 'status', 'email_verified_at')->first();
        $response = ['success' => true, 'message' => 'If the account exists, a verification token was created'];

        if ($user && empty($user->email_verified_at) && $user->status === 'pending') {
            DB::table('email_verifications')->where('user_id', $user->id)->delete();
            $token = $this->jwt->emailToken();
            DB::table('email_verifications')->insert([
                'user_id' => $user->id,
                'token' => $token,
                'expires_at' => now()->addDay(),
            ]);
            if (app()->environment('local')) $response['verification_token'] = $token;
        }

        return response()->json($response);
    }
}
