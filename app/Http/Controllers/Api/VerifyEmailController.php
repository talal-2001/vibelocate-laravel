<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\Auth\JwtService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Throwable;

class VerifyEmailController extends Controller
{
    public function __construct(private JwtService $jwt)
    {
    }

    public function __invoke(Request $request)
    {
        /*
        |--------------------------------------------------------------------------
        | Verify using email + OTP
        |--------------------------------------------------------------------------
        */
        if ($request->has('otp')) {
            return $this->verifyOtp($request);
        }

        /*
        |--------------------------------------------------------------------------
        | Old verification method using token
        |--------------------------------------------------------------------------
        */
        return $this->verifyToken($request);
    }

    private function verifyOtp(Request $request)
    {
        $email = strtolower(trim((string) $request->input('email', '')));
        $otp   = trim((string) $request->input('otp', ''));

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->error('Invalid email address', 422);
        }

        if ($otp === '' || !preg_match('/^\d{6}$/', $otp)) {
            return $this->error('Please enter the complete verification code', 422);
        }

        /*
        |--------------------------------------------------------------------------
        | Find user
        |--------------------------------------------------------------------------
        */
        $user = DB::table('users')
            ->where('email', $email)
            ->whereNull('deleted_at')
            ->first();

        if (!$user) {
            return $this->error('User not found', 404);
        }

        /*
        |--------------------------------------------------------------------------
        | Already verified
        |--------------------------------------------------------------------------
        */
        if ($user->email_verified_at !== null) {
            return $this->successResponse($user);
        }

        /*
        |--------------------------------------------------------------------------
        | Check OTP
        |--------------------------------------------------------------------------
        */
        $verification = DB::table('email_verifications')
            ->where('user_id', $user->id)
            ->where('token', $otp)
            ->where('expires_at', '>', now())
            ->first();

        if (!$verification) {
            return $this->error(
                'Invalid or expired verification code',
                400
            );
        }

        return $this->completeVerification($user);
    }

    private function verifyToken(Request $request)
    {
        $token = trim((string) (
            $request->isMethod('get')
                ? $request->query('token', '')
                : $request->input('token', '')
        ));

        if ($token === '') {
            return $this->error(
                'Verification token is required',
                422
            );
        }

        $verification = DB::table('email_verifications')
            ->where('token', $token)
            ->where('expires_at', '>', now())
            ->select('user_id')
            ->first();

        if (!$verification) {
            return $this->error(
                'Invalid or expired verification token',
                400
            );
        }

        $user = DB::table('users')
            ->where('id', $verification->user_id)
            ->whereNull('deleted_at')
            ->first();

        if (!$user) {
            return $this->error('User not found', 404);
        }

        return $this->completeVerification($user);
    }

    private function completeVerification($user)
    {
        DB::beginTransaction();

        try {
            /*
            |--------------------------------------------------------------------------
            | Activate user
            |--------------------------------------------------------------------------
            */
            DB::table('users')
                ->where('id', $user->id)
                ->update([
                    'email_verified_at' => now(),
                    'status'            => 'active',
                ]);

            /*
            |--------------------------------------------------------------------------
            | Delete used OTP
            |--------------------------------------------------------------------------
            */
            DB::table('email_verifications')
                ->where('user_id', $user->id)
                ->delete();

            /*
            |--------------------------------------------------------------------------
            | Generate access + refresh tokens
            |--------------------------------------------------------------------------
            */
            $accessToken = $this->jwt->accessToken(
                (int) $user->id,
                $user->email
            );

            $refreshToken = $this->jwt->refreshToken();

            DB::table('refresh_tokens')->insert([
                'user_id'    => $user->id,
                'device_id'  => null,
                'token_hash' => hash('sha256', $refreshToken),
                'expires_at' => now()->addDays(7),
            ]);

            DB::commit();

            return response()->json([
                'success'       => true,
                'message'       => 'Email verified successfully',
                'access_token'  => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type'    => 'bearer',
                'expires_in'    => 900,
            ]);

        } catch (Throwable $e) {
            DB::rollBack();

            report($e);

            return $this->error(
                'Email verification failed',
                500
            );
        }
    }

    private function successResponse($user)
    {
        try {
            $accessToken = $this->jwt->accessToken(
                (int) $user->id,
                $user->email
            );

            return response()->json([
                'success'      => true,
                'message'      => 'Email already verified',
                'access_token' => $accessToken,
                'token_type'   => 'bearer',
                'expires_in'   => 900,
            ]);

        } catch (Throwable $e) {
            report($e);

            return $this->error(
                'Unable to generate access token',
                500
            );
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