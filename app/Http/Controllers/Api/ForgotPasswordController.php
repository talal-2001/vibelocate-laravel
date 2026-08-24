<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

class ForgotPasswordController extends Controller
{
    public function __invoke(Request $request)
    {
        $email = strtolower(trim((string) $request->input('email', '')));

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid email address',
            ], 422);
        }

        $user = DB::table('users')
            ->where('email', $email)
            ->whereNull('deleted_at')
            ->select('id', 'first_name', 'email')
            ->first();

        if (!$user) {
            return response()->json([
                'success' => true,
                'message' => 'If the email exists, a verification code was sent',
            ]);
        }

        // حذف أي كود قديم
        DB::table('password_resets')
            ->where('email', $email)
            ->delete();

        // إنشاء OTP من 6 أرقام
        $otp = (string) random_int(100000, 999999);

        DB::table('password_resets')->insert([
            'email' => $email,
            'token' => $otp,
            'expires_at' => now()->addMinutes(10),
        ]);

        try {
            Mail::raw(
                "Your VibeLocate AI password reset verification code is: {$otp}\n\n"
                . "This code will expire in 10 minutes.\n\n"
                . "If you did not request a password reset, you can ignore this email.",
                function ($message) use ($email) {
                    $message->to($email)
                        ->subject('VibeLocate AI - Password Reset Verification Code');
                }
            );
        } catch (\Throwable $e) {
            DB::table('password_resets')
                ->where('email', $email)
                ->delete();

            return response()->json([
                'success' => false,
                'message' => 'Could not send verification code',
                'details' => app()->environment('local')
                    ? $e->getMessage()
                    : null,
            ], 500);
        }

        return response()->json([
            'success' => true,
            'message' => 'Verification code sent to your email',
        ]);
    }
}