export class ApiResponse {
  constructor(statusCode, data, message = "Success") {
    this.statusCode = statusCode;
    this.data = data;
    this.message = message;
    this.success = statusCode < 400;
  }
}

export const ok = (res, data, message = "Success", status = 200) =>
  res.status(status).json(new ApiResponse(status, data, message));
