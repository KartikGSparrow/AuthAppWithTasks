using AuthAppNew.Responses;
using AuthAppNew.Responses.TasksApi.Responses;

namespace AuthAppNew.Interfaces
{
    public interface ITaskService
    {
        Task<GetTasksResponse> GetTasks(int userId);
        Task<SaveTaskResponse> SaveTask(Models.Task task);
        Task<DeleteTaskResponse> DeleteTask(int taskId, int userId);
    }
}