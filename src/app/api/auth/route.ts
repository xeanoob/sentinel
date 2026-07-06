import { NextResponse } from "next/server";
import { cookies } from "next/headers";

export async function POST(request: Request) {
  try {
    const { password } = await request.json();
    
    // Check against the environment variable. If not set, default to "admin" for development.
    const masterPassword = process.env.ADMIN_PASSWORD || "admin";

    if (password === masterPassword) {
      // Set an HTTP-only cookie
      const cookieStore = await cookies();
      cookieStore.set("sentinel_auth", "authenticated", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 60 * 60 * 24 * 7, // 1 week
        path: "/",
      });

      return NextResponse.json({ success: true });
    }

    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  } catch (error) {
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}

export async function DELETE() {
  // Logout endpoint
  const cookieStore = await cookies();
  cookieStore.delete("sentinel_auth");
  return NextResponse.json({ success: true });
}
