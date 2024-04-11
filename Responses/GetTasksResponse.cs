namespace AuthAppNew.Responses
{
    public class GetTasksResponse : BaseResponse
    {
        public List<Models.Task> Tasks { get; set; }
    }
}