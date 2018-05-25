#pragma once
#include "Includes.h"
#include <fstream>
#include <string>
#include <tchar.h>
#include <experimental/filesystem>
#define M_PI 3.14159265358979323846264338327950288419716939937510

class Vector2
{
public:
	Vector2() : x(0.f), y(0.f)
	{

	}

	Vector2(float _x, float _y) : x(_x), y(_y)
	{

	}
	~Vector2()
	{

	}

	float x;
	float y;
};
class Vector3
{
public:
	Vector3() : x(0.f), y(0.f), z(0.f)
	{

	}

	Vector3(float _x, float _y, float _z) : x(_x), y(_y), z(_z)
	{

	}
	~Vector3()
	{

	}

	float x;
	float y;
	float z;

	inline float Dot(Vector3 v)
	{
		return x * v.x + y * v.y + z * v.z;
	}

	inline float Distance(Vector3 v)
	{
		return float(sqrtf(powf(v.x - x, 2.0) + powf(v.y - y, 2.0) + powf(v.z - z, 2.0)));
	}

	Vector3 operator+(Vector3 v)
	{
		return Vector3(x + v.x, y + v.y, z + v.z);
	}

	Vector3 operator-(Vector3 v)
	{
		return Vector3(x - v.x, y - v.y, z - v.z);
	}

	Vector3 operator*(float number) const {
		return Vector3(x * number, y * number, z * number);
	}
};
class Vector4
{
public:
	Vector4() : x(0.f), y(0.f), z(0.f), w(0.f)
	{

	}

	Vector4(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w)
	{

	}
	~Vector4()
	{

	}

	float x;
	float y;
	float z;
	float w;
};

class utilities 
{
public:
	ULONG get_pid(std::string _process);
	HWND get_window(LPCSTR _windowName);
	HANDLE get_handle(ULONG _process, ULONG _desiredAccess, bool _protect);
	uintptr_t get_base(ULONG _processId, TCHAR *_module);
	ULONG find_pattern(HANDLE _handle, ULONG _base, ULONG _len, BYTE* _pat, char* _mask, int _offset = 0);
	bool set_debug(bool _status);
	bool nop_bytes(HANDLE _handle, uintptr_t _address, SIZE_T _size);
	void erase_pe();
	bool file_exists(std::string _file);
	template <typename T> T RPM(HANDLE _handle, SIZE_T _address);
	template <typename T> T WPM(HANDLE _handle, SIZE_T _address, T _data);
};

extern utilities g_Utils;