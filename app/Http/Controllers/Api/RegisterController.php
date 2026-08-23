<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
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

        // Validation
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

        if (DB::table('users')->where('email', $email)->exists()) {
            return $this->error('Email already registered', 409);
        }

        if ($phone !== '' && DB::table('users')->where('phone', $phone)->exists()) {
            return $this->error('Phone already registered', 409);
        }

        DB::beginTransaction();

        try {
            // Create user
            $userId = DB::table('users')->insertGetId([
                'first_name'    => $firstName,
                'last_name'     => $lastName,
                'email'         => $email,
                'phone'         => $phone !== '' ? $phone : null,
                'password_hash' => Hash::make($password),
                'status'        => 'pending',
            ]);

            // Assign role
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

            // Create profile
            DB::table('user_profiles')->insert([
                'user_id'            => $userId,
                'preferred_language' => 'en',
                'currency'           => 'AED',
            ]);

            // Generate 6-digit OTP
            $otp = (string) random_int(100000, 999999);

            // Remove any previous verification codes
            DB::table('email_verifications')
                ->where('user_id', $userId)
                ->delete();

            // Save OTP
            DB::table('email_verifications')->insert([
                'user_id'    => $userId,
                'token'      => $otp,
                'expires_at' => now()->addMinutes(10),
            ]);

            // Create referral code
            $referralCode = strtoupper(
                'VIBE-' . $userId . '-' . bin2hex(random_bytes(3))
            );

            DB::table('referral_codes')->insert([
                'user_id' => $userId,
                'code'    => $referralCode,
            ]);

            /*
             * Send OTP through Brevo SMTP
             */
            $fullName = $firstName . ' ' . $lastName;

            $html = '
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>

                <body style="
                    margin:0;
                    padding:0;
                    background:#f4f6f8;
                    font-family:Arial,Helvetica,sans-serif;
                ">

                    <div style="
                        max-width:600px;
                        margin:40px auto;
                        background:#ffffff;
                        border-radius:14px;
                        overflow:hidden;
                        box-shadow:0 4px 20px rgba(0,0,0,0.08);
                    ">

                        <div style="
                            background:#102b55;
                            padding:30px;
                            text-align:center;
                            color:white;
                        ">
                            <h1 style="
                                margin:0;
                                font-size:28px;
                            ">
                                VibeLocate AI
                            </h1>
                        </div>

                        <div style="
                            padding:35px;
                            text-align:center;
                        ">

                            <h2 style="
                                color:#102b55;
                                margin-top:0;
                            ">
                                Verify your email
                            </h2>

                            <p style="
                                color:#555;
                                font-size:16px;
                            ">
                                Hello ' . e($fullName) . ',
                            </p>

                            <p style="
                                color:#555;
                                font-size:16px;
                            ">
                                Use the verification code below to complete your
                                VibeLocate AI registration.
                            </p>

                            <div style="
                                margin:30px auto;
                                font-size:36px;
                                font-weight:bold;
                                letter-spacing:10px;
                                color:#102b55;
                                background:#eef4ff;
                                padding:20px;
                                border-radius:12px;
                                width:fit-content;
                            ">
                                ' . e($otp) . '
                            </div>

                            <p style="
                                color:#777;
                                font-size:14px;
                            ">
                                This code will expire in 10 minutes.
                            </p>

                            <p style="
                                color:#777;
                                font-size:14px;
                            ">
                                If you did not create a VibeLocate AI account,
                                you can safely ignore this email.
                            </p>

                        </div>

                        <div style="
                            padding:20px;
                            background:#f8f9fa;
                            text-align:center;
                            color:#888;
                            font-size:12px;
                        ">
                            © ' . date('Y') . ' VibeLocate AI
                        </div>

                    </div>

                </body>
                </html>
            ';

            Mail::html($html, function ($message) use ($email, $fullName) {
                $message
                    ->to($email, $fullName)
                    ->subject('Your VibeLocate AI Verification Code');
            });

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Registration successful. Verification code sent to your email.',
                'user_id' => $userId,
                'email'   => $email,
                'otp_expires_in' => 600,
            ], 201, [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        } catch (Throwable $e) {
            DB::rollBack();

            report($e);

            return response()->json([
                'success' => false,
                'message' => 'Registration failed',
                'details' => app()->environment('local')
                    ? $e->getMessage()
                    : null,
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