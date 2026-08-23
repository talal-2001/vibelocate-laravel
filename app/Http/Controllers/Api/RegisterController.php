<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Throwable;

class RegisterController extends Controller
{
    public function __invoke(Request $request)
    {
        $firstName = trim((string) $request->input('first_name', ''));
        $lastName  = trim((string) $request->input('last_name', ''));
        $email     = strtolower(trim((string) $request->input('email', '')));
        $phone     = trim((string) $request->input('phone', ''));
        $password  = (string) $request->input('password', '');
        $roleSlug  = (string) $request->input('role_slug', 'tenant');

        if ($firstName === '' || $lastName === '') {
            return $this->error('First name and last name are required', 422);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->error('Invalid email address', 422);
        }

        if (strlen($password) < 8) {
            return $this->error('Password must be at least 8 characters', 422);
        }

        if (!in_array($roleSlug, ['tenant', 'owner'], true)) {
            return $this->error('Invalid registration role', 422);
        }

        try {
            if (DB::table('users')->where('email', $email)->exists()) {
                return $this->error('Email already registered', 409);
            }

            if (
                $phone !== '' &&
                DB::table('users')->where('phone', $phone)->exists()
            ) {
                return $this->error('Phone already registered', 409);
            }

            DB::beginTransaction();

            $userId = DB::table('users')->insertGetId([
                'first_name'    => $firstName,
                'last_name'     => $lastName,
                'email'         => $email,
                'phone'         => $phone !== '' ? $phone : null,
                'password_hash' => Hash::make($password),
                'status'        => 'pending',
            ]);

            $role = DB::table('roles')
                ->where('slug', $roleSlug)
                ->first();

            if (!$role) {
                throw new \RuntimeException('Role not found');
            }

            DB::table('user_roles')->insert([
                'user_id' => $userId,
                'role_id' => $role->id,
            ]);

            DB::table('user_profiles')->insert([
                'user_id'            => $userId,
                'preferred_language' => 'en',
                'currency'           => 'AED',
            ]);

            $otp = (string) random_int(100000, 999999);

            DB::table('email_verifications')
                ->where('user_id', $userId)
                ->delete();

            DB::table('email_verifications')->insert([
                'user_id'    => $userId,
                'token'      => $otp,
                'expires_at' => now()->addMinutes(10),
            ]);

            $referralCode = strtoupper(
                'VIBE-' . $userId . '-' . bin2hex(random_bytes(3))
            );

            DB::table('referral_codes')->insert([
                'user_id' => $userId,
                'code'    => $referralCode,
            ]);

            DB::commit();

            $fullName = trim($firstName . ' ' . $lastName);

            $htmlContent = '
            <!DOCTYPE html>
            <html>
            <body style="font-family:Arial,sans-serif;background:#f4f7fb;padding:30px;">
                <div style="max-width:600px;margin:auto;background:#ffffff;border-radius:14px;overflow:hidden;">
                    <div style="background:#17365f;color:#ffffff;padding:30px;text-align:center;">
                        <h1 style="margin:0;">VibeLocate AI</h1>
                    </div>

                    <div style="padding:35px;text-align:center;">
                        <h2 style="color:#17365f;">Verify your email</h2>

                        <p>Hello ' . e($fullName) . ',</p>

                        <p>Use this verification code to complete your registration:</p>

                        <div style="
                            display:inline-block;
                            margin:25px 0;
                            padding:18px 28px;
                            background:#eef4ff;
                            border-radius:12px;
                            font-size:36px;
                            font-weight:bold;
                            letter-spacing:8px;
                            color:#17365f;
                        ">
                            ' . e($otp) . '
                        </div>

                        <p>This code expires in 10 minutes.</p>
                    </div>
                </div>
            </body>
            </html>';

            $brevoResponse = Http::timeout(20)
                ->withHeaders([
                    'api-key' => env('BREVO_API_KEY'),
                    'accept' => 'application/json',
                    'content-type' => 'application/json',
                ])
                ->post('https://api.brevo.com/v3/smtp/email', [
                    'sender' => [
                        'name' => env('BREVO_SENDER_NAME', 'VibeLocate AI'),
                        'email' => env('BREVO_SENDER_EMAIL'),
                    ],
                    'to' => [
                        [
                            'email' => $email,
                            'name' => $fullName,
                        ]
                    ],
                    'subject' => 'Your VibeLocate AI Verification Code',
                    'htmlContent' => $htmlContent,
                ]);

            if (!$brevoResponse->successful()) {
                throw new \RuntimeException(
                    'Brevo API error: ' .
                    $brevoResponse->status() .
                    ' - ' .
                    $brevoResponse->body()
                );
            }

            return response()->json([
                'success' => true,
                'message' => 'Registration successful. Verification code sent to your email.',
                'user_id' => $userId,
                'email' => $email,
                'verification_required' => true,
                'otp_expires_in' => 600,
            ], 201, [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        } catch (Throwable $e) {
            if (DB::transactionLevel() > 0) {
                DB::rollBack();
            }

            report($e);

            return response()->json([
                'success' => false,
                'message' => 'Registration failed',
            ], 500);
        }
    }

    private function error(string $message, int $status)
    {
        return response()->json([
            'success' => false,
            'message' => $message,
        ], $status);
    }
}